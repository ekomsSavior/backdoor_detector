
rule backdoor_indicator {
    meta:
        description = "Common backdoor signatures"
        author = "BackdoorDetector"
        severity = "HIGH"
    strings:
        $socket_create = "socket("
        $bind = "bind("
        $listen = "listen("
        $accept = "accept("
        $shell = /bin[/\\]?(?:sh|bash|cmd|powershell)/
        $backdoor_strings = { 
            "backdoor" "shell" "reverse" "bind" "port" "1337" "31337" 
            "meterpreter" "beacon" "c2" "command and control"
        }
    condition:
        any of ($backdoor_strings) and 2 of ($socket_create, $bind, $listen, $accept)
}

rule suspicious_network_activity {
    meta:
        description = "Suspicious network operations"
        severity = "MEDIUM"
    strings:
        $raw_socket = "SOCK_RAW"
        $packet_sniff = "recvfrom("
        $packet_send = "sendto("
        $promiscuous = "PROMISC"
    condition:
        ($raw_socket and $packet_sniff) or $promiscuous
}

rule credential_theft {
    meta:
        description = "Potential credential theft indicators"
        severity = "HIGH"
    strings:
        $password_keys = { 
            "password" "passwd" "pwd" "secret" "token" "key" "credential" 
            "auth" "login" "authentication"
        }
        $storage_patterns = {
            "keychain" "credential manager" "keyring" "password manager"
            "lsass" "securityd" "gnome-keyring"
        }
        $exfil_patterns = {
            "upload" "send" "post" "exfiltrate" "exfiltration" "export" "dump"
        }
    condition:
        any of ($password_keys) and any of ($storage_patterns) and any of ($exfil_patterns)
}

rule persistence_mechanisms {
    meta:
        description = "Common persistence mechanisms"
        severity = "MEDIUM"
    strings:
        $registry_run = "CurrentVersion\\Run"
        $service_install = "CreateService"
        $cron_job = "cron"
        $launch_agent = "LaunchAgent"
        $startup_folder = "Start Menu\\Programs\\Startup"
        $scheduled_task = "CreateTask"
    condition:
        any of them
}
