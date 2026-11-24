"""Workload sources for actual language interoperability contracts."""
import json

LANGUAGES = ("python", "java", "go", "typescript", "bash", "javascript")
SAMPLES = {
    "python": (
        "import os\nassert 20000 <= os.getuid() < 20004 and os.getgid() == 1000 and os.getgroups() == []\n"
        "assert 'CapEff:\\t0000000000000000' in open('/proc/self/status').read()\n"
        "probe_value=40\nopen('/workspace/lang-replay-python','a').write('x')\nprint('kernel-start')",
        "probe_value += 2\nprint(probe_value)\nprobe_value",
        "raise ValueError('expected language exception')",
    ),
    "java": (
        'import java.nio.file.*;\n'
        'String ghStatus=Files.readString(Path.of("/proc/self/status"));\n'
        'long ghUid=new java.util.Scanner(ghStatus.lines().filter(line->line.startsWith("Uid:")).findFirst().orElseThrow().substring(4)).nextLong();\n'
        'long ghGid=new java.util.Scanner(ghStatus.lines().filter(line->line.startsWith("Gid:")).findFirst().orElseThrow().substring(4)).nextLong();\n'
        'String ghGroups=ghStatus.lines().filter(line->line.startsWith("Groups:")).findFirst().orElseThrow().substring(7).trim();\n'
        'if (ghUid<20000 || ghUid>=20004 || ghGid!=1000 || !ghGroups.isEmpty()) throw new IllegalStateException("identity");\n'
        'if (!ghStatus.contains("CapEff:\\t0000000000000000") || !ghStatus.contains("NoNewPrivs:\\t1")) throw new IllegalStateException("capabilities");\n'
        'int probeValue = 40;\n'
        'Files.writeString(Path.of("/workspace/lang-replay-java"), "x", StandardOpenOption.CREATE, StandardOpenOption.APPEND);\n'
        'System.out.println("kernel-start");',
        'probeValue += 2;\nSystem.out.println(probeValue);\nprobeValue',
        'throw new IllegalStateException("expected language exception");',
    ),
    "go": (
        'import ("fmt"; "os"; "syscall"; "strings")\n'
        'if os.Getuid()<20000 || os.Getuid()>=20004 || os.Getgid()!=1000 { panic("identity") }\n'
        'ghGroups, _ := syscall.Getgroups(); if len(ghGroups)!=0 { panic("groups") }\n'
        'ghStatus, _ := os.ReadFile("/proc/self/status"); if !strings.Contains(string(ghStatus), "CapEff:\\t0000000000000000") { panic("capabilities") }\n'
        'probeValue := 40\n'
        'ghFile, _ := os.OpenFile("/workspace/lang-replay-go", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0660); ghFile.WriteString("x"); ghFile.Close()\n'
        'fmt.Println("kernel-start")',
        'probeValue += 2\nfmt.Println(probeValue)',
        'panic("expected language exception")',
    ),
    "bash": (
        'test "$(id -u)" -ge 20000 && test "$(id -u)" -lt 20004 && test "$(id -g)" = 1000 && test "$(id -G)" = 1000 && '
        'grep -q "CapEff:[[:space:]]*0000000000000000" /proc/self/status && '
        'probe_value=40 && printf x >>/workspace/lang-replay-bash && printf "kernel-start\\n"',
        'probe_value=$((probe_value+2)); printf "%s\\n" "$probe_value"',
        'false',
    ),
}
for _language in ("typescript", "javascript"):
    SAMPLES[_language] = (
        'var ghFs = require("fs");\n'
        'if (process.getuid()<20000 || process.getuid()>=20004 || process.getgid()!=1000 || !process.getgroups().every(group=>group===1000)) throw new Error("identity");\n'
        'if (!ghFs.readFileSync("/proc/self/status","utf8").includes("CapEff:\\t0000000000000000")) throw new Error("capabilities");\n'
        + ('var probeValue: number = 40;\n' if _language == "typescript" else 'var probeValue = 40;\n')
        + f'ghFs.appendFileSync("/workspace/lang-replay-{_language}","x");\nconsole.log("kernel-start");',
        'probeValue += 2;\nconsole.log(probeValue);',
        'throw new Error("expected language exception");',
    )


def blocking(language, marker):
    # An interactive Bash background job can already be a process-group leader.
    # Fork once before setsid so every language creates an actual escaped child.
    child = "import os,time\nif os.fork(): os._exit(0)\nos.setsid()\nassert os.getsid(0)==os.getpid()\nopen(" + repr('/workspace/' + marker) + ",'w').write(str(os.getpid()))\ntime.sleep(90)"
    quoted = json.dumps(child)
    if language == "python":
        return f"import subprocess,time\nsubprocess.Popen(['python3','-I','-c',{child!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\ntime.sleep(90)"
    if language == "java":
        return f'new ProcessBuilder("python3","-I","-c",{quoted}).start();\nThread.sleep(90000);'
    if language == "go":
        return f'import ("os/exec"; "time")\nghChild := exec.Command("python3","-I","-c",{quoted}); ghChild.Start(); time.Sleep(90*time.Second)'
    if language == "bash":
        # The shell only interprets this intentionally supplied workload source.
        # The Rust platform still launches kernels with literal argv.
        import shlex
        return f"python3 -I -c {shlex.quote(child)} >/dev/null 2>&1 &\nsleep 90"
    return f'var ghChild = require("child_process").spawn("python3",["-I","-c",{quoted}],{{detached:false,stdio:"ignore"}}); ghChild.unref();\nawait new Promise(resolve=>setTimeout(resolve,90000));'
