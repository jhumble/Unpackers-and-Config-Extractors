rule interesting_strings {
    strings:
        $domain = /[a-zA-Z0-9-.]{3,}\.(com|net|gov|cn|org|info|ru|ca|us)[^a-zA-Z0-9\/\?=]/ nocase wide ascii
        $url = /http.?:\/\/[a-zA-Z0-9_\-.%\/\?=\&]+/ nocase wide ascii
        $filename = /[a-zA-Z0-9_\-\\.\/:]{1,}\.(exe|dll|zip|rar|cfg|conf|cfg|lnk|ini|xml|docx|doc|xlsx|xls|ps1|bat|sys)/ nocase wide ascii
        $url2 = /[a-zA-Z]{3,}:\/\/[a-zA-Z-]{2,}[a-zA-Z0-9\/\.?=]+/ nocase wide ascii
        $api = /(Create|Virtual|Reg|Read|Write|Open)[A-Z][A-Za-z _\.-]+/ wide ascii
        $strings = /[a-zA-Z0-9 _\-.%\/\\]*(connect|autoit|explorer|host|start|root|server|pass|process|user|shell|open|virt|bits|admin|temp|registry)[a-zA-Z0-9 _\-.%\/\\]*/ nocase wide ascii
        $strings2 = /[^a-zA-Z0-9](win|cmd|reg|Reg|CMD|Cmd|Win|WIN)[a-zA-Z _\-.%\/]+/ wide ascii
        $user_agent = /Mozilla[a-zA-Z0-9-\(\);,.\/ \:]+/ nocase wide ascii
        $key = /----BEGIN.{,1024}----/ wide ascii
        $pipe = /\\\\[a-zA-Z0-9_\-\\.\/:%]{2,}\\[a-zA-Z0-9_\-\\.\/:%]{,100}/ wide ascii nocase
        $ip = /([0-9]{1,3}\.){3}[0-9]{1,3}[\/0-9a-z.%\t]{1,}/ wide ascii nocase
        $bazar = /[a-zA-Z0-9_\-]+.bazar/ wide ascii nocase

        /*
            007600B6 | 55                       | push ebp                                |
            007600B7 | 8BEC                     | mov ebp,esp                             |
            007600B9 | 83EC 14                  | sub esp,14                              |
        */
        $code = {55 8B EC 83 EC}
    condition:
        any of them
}
