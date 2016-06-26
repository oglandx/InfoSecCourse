##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::WmapScanSSL
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  include Rex::Socket::Comm


 	# функция инициализации, позволяет указать параметры модуля
  def initialize
    super(
      'Name'        => 'HTTP SSL Certificate Information',
      'Description' => 'Parse the server SSL certificate to obtain the common name and signature algorithm',
      'Author'      =>
        [
          'et', #original module
          'Chris John Riley', #additions
          'Veit Hailperin <hailperv[at]gmail.com>', # checks for public key size, valid time
        ],
      'License'     => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(443)
    ], self.class)
  end

  # главная функция
  def run_host(ip)

    begin

    	# соединяемся с хостом, получаем сертификат, затем отсоединяемся от хоста
      connect(true, {"SSL" => true}) #Force SSL

      if sock.respond_to? :peer_cert
        cert = OpenSSL::X509::Certificate.new(sock.peer_cert)
      end

      disconnect


      # если успешно подключились и получили сертификат
      if cert
        print_status("Subject: #{cert.subject}")
        print_status("Issuer: #{cert.issuer}")
        print_status("Signature Alg: #{cert.signature_algorithm}")

        # в зависимости от того, используем ECDSA или RSA, метрики размера ключа различны
        public_key_size = 0
        if cert.public_key.respond_to? :n
          public_key_size = cert.public_key.n.num_bytes * 8
          print_status("Public Key Size: #{public_key_size} bits")
        end
        print_status("Not Valid Before: #{cert.not_before}")
        print_status("Not Valid After: #{cert.not_after}")

        # проверяем общие свойства самоподписанных сертификатов
        caissuer = (/CA Issuers - URI:(.*?),/i).match(cert.extensions.to_s)

        # 1) если сертификат не содержит расширения CA
        if caissuer.to_s.empty?
          print_good("Certificate contains no CA Issuers extension... possible self signed certificate")
        else
          print_status(caissuer.to_s[0..-2])
        end

        # 2) если издатель совпадает с субъектом сертификата
        if cert.issuer.to_s == cert.subject.to_s
          print_good("Certificate Subject and Issuer match... possible self signed certificate")
        end

        # проверяем алгоритм сертификата
        alg = cert.signature_algorithm

        # если находим "md5", значит MD5 (скомпрометирован)
        if alg.downcase.include? "md5"
          print_status("WARNING: Signature algorithm using MD5 (#{alg})")
        end

        # получаем имя хоста
        vhostn = nil
        cert.subject.to_a.each do |n|
          vhostn = n[1] if n[0] == 'CN'
        end

        # проверяем длину ключа: если 1024 или меньше бит, то ключ слабый
        if public_key_size > 0
          if public_key_size == 1024
            print_status("WARNING: Public Key only 1024 bits")
          elsif public_key_size < 1024
            print_status("WARNING: Weak Public Key: #{public_key_size} bits")
          end
        end

        # проверяем валидность ключа

        # 1) если срок действия истёк
        if cert.not_after < Time.now
          print_status("WARNING: Certificate not valid anymore")
        end

        # 2) если ещё не начал действовать
        if cert.not_before > Time.now
          print_status("WARNING: Certificate not valid yet")
        end

        # если сумели достать имя хоста
        if vhostn
          print_status("Has common name #{vhostn}")

          # сохраняем имя виртуального хоста для HTTP
          report_note(
            :host	=> ip,
            :port	=> rport,
            :proto  => 'tcp',
            :type	=> 'http.vhost',
            :data	=> {:name => vhostn}
          )

          # сохраняем содержимое сертификата
          report_note(
            :host	=> ip,
            :proto  => 'tcp',
            :port	=> rport,
            :type	=> 'ssl.certificate',
            :data	=> {
              :cn        => vhostn,
              :subject   => cert.subject.to_a,
              :algorithm => alg,
              :valid_from => cert.not_before,
              :valid_after => cert.not_after,
              :key_size => public_key_size

            }
          )

          # если нужно, обновляем имя сервера
          if vhostn !~ /localhost|snakeoil/i
            report_host(
              :host => ip,
              :name => vhostn
            )
          end

        end
      else
        print_status("No certificate subject or common name found")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
