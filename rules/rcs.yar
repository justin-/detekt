rule RCS_Scout
{
    meta:
        detection = "Hacking Team RCS Scout"

    strings:
        $filter1 = "$engine5"
        $filter2 = "$start4"
        $filter3 = "$upd2"
        $filter4 = "$lookma6"

        $engine1 = /(E)ngine started/ wide ascii
        $engine2 = /(R)unning in background/ wide ascii
        $engine3 = /(L)ocking doors/ wide ascii
        $engine4 = /(R)otors engaged/ wide ascii
        $engine5 = /(I)\'m going to start it/ wide ascii

        $start1 = /Starting upgrade\!/ wide ascii
        $start2 = /(I)\'m going to start the program/ wide ascii
        $start3 = /(i)s it ok\?/ wide ascii
        $start4 = /(C)lick to start the program/ wide ascii

        $upd1 = /(U)pdJob/ wide ascii
        $upd2 = /(U)pdTimer/ wide ascii

        $lookma1 = /(O)wning PCI bus/ wide
        $lookma2 = /(F)ormatting bios/ wide
        $lookma3 = /(P)lease insert a disk in drive A:/ wide
        $lookma4 = /(U)pdating CPU microcode/ wide
        $lookma5 = /(N)ot sure what's happening/ wide
        $lookma6 = /(L)ook ma, no thread id\! \\\\o\// wide        

        $rcs94_batch1 = /437890\.bat/ wide ascii
        $rcs94_batch2 = /124904\.bat/ wide ascii
        $rcs94_batch3 = /391294\.bat/ wide ascii

        $rcs95_batch1 = /9348690\.bat/ wide
        $rcs95_batch2 = /4204902\.bat/ wide
        $rcs95_batch3 = /6913291\.bat/ wide

        $rcs96_batch1 = /3984096\.bat/ wide
        $rcs96_batch2 = /2094402\.bat/ wide
        $rcs96_batch3 = /1926319\.bat/ wide

    condition:
        (all of ($engine*) or all of ($start*) or all of ($upd*) or 4 of ($lookma*) or all of ($rcs94_batch*) or all of ($rcs95_batch*) or all of ($rcs96_batch*)) and not any of ($filter*)
}

rule RCS_Backdoor
{
    meta:
        detection = "Hacking Team RCS Backdoor"

    strings:
        $filter1 = "$debug3"
        $filter2 = "$log2"
        $filter3 = "error2"

        $debug1 = /\- (C)hecking components/ wide ascii
        $debug2 = /\- (A)ctivating hiding system/ wide ascii
        $debug3 = /(f)ully operational/ wide ascii

        $log1 = /\- Browser activity \(FF\)/ wide ascii
        $log2 = /\- Browser activity \(IE\)/ wide ascii
        
        // Cause false positives.
        //$log3 = /\- About to call init routine at %p/ wide ascii
        //$log4 = /\- Calling init routine at %p/ wide ascii

        $error1 = /\[Unable to deploy\]/ wide ascii
        $error2 = /\[The system is already monitored\]/ wide ascii

    condition:
        (2 of ($debug*) or 2 of ($log*) or all of ($error*)) and not any of ($filter*)
}
