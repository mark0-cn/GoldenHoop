use goldenhoop_protocol::CodeLanguage;

pub(super) fn sources(language: CodeLanguage) -> (&'static str, &'static str, &'static str) {
    match language {
        CodeLanguage::Python => (
            "import os\nassert 20000<=os.getuid()<20004 and os.getgid()==1000 and os.getgroups()==[]\nassert 'CapEff:\\t0000000000000000' in open('/proc/self/status').read()\nprobe_value=40\nopen('/workspace/goldenhoop-probe-once','a').write('x')\nprint('kernel-start')",
            "probe_value+=2\nprint(probe_value)\nprobe_value",
            "raise ValueError('expected probe exception')",
        ),
        CodeLanguage::Java => (
            r#"import java.nio.file.*;
String ghStatus=Files.readString(Path.of("/proc/self/status"));
long ghUid=new java.util.Scanner(ghStatus.lines().filter(line->line.startsWith("Uid:")).findFirst().orElseThrow().substring(4)).nextLong();
long ghGid=new java.util.Scanner(ghStatus.lines().filter(line->line.startsWith("Gid:")).findFirst().orElseThrow().substring(4)).nextLong();
String ghGroups=ghStatus.lines().filter(line->line.startsWith("Groups:")).findFirst().orElseThrow().substring(7).trim();
if (ghUid<20000 || ghUid>=20004 || ghGid!=1000 || !ghGroups.isEmpty()) throw new IllegalStateException("identity");
if (!ghStatus.contains("CapEff:\t0000000000000000") || !ghStatus.contains("NoNewPrivs:\t1")) throw new IllegalStateException("capabilities");
int probeValue = 40;
Files.writeString(Path.of("/workspace/goldenhoop-probe-once"),"x",StandardOpenOption.CREATE,StandardOpenOption.APPEND);
System.out.println("kernel-start");"#,
            "probeValue+=2;\nSystem.out.println(probeValue);\nprobeValue",
            "throw new IllegalStateException(\"expected probe exception\");",
        ),
        CodeLanguage::Go => (
            r#"import ("fmt"; "os"; "syscall"; "strings")
if os.Getuid()<20000 || os.Getuid()>=20004 || os.Getgid()!=1000 { panic("identity") }
ghGroups, _ := syscall.Getgroups(); if len(ghGroups)!=0 { panic("groups") }
ghStatus, _ := os.ReadFile("/proc/self/status"); if !strings.Contains(string(ghStatus), "CapEff:\t0000000000000000") { panic("capabilities") }
probeValue := 40
ghFile, _ := os.OpenFile("/workspace/goldenhoop-probe-once",os.O_CREATE|os.O_APPEND|os.O_WRONLY,0660); ghFile.WriteString("x"); ghFile.Close()
fmt.Println("kernel-start")"#,
            "probeValue+=2\nfmt.Println(probeValue)",
            "panic(\"expected probe exception\")",
        ),
        CodeLanguage::Bash => (
            r#"test "$(id -u)" -ge 20000 && test "$(id -u)" -lt 20004 && test "$(id -g)" = 1000 && test "$(id -G)" = 1000 && grep -q "CapEff:[[:space:]]*0000000000000000" /proc/self/status && probe_value=40 && printf x >>/workspace/goldenhoop-probe-once && printf 'kernel-start\n'"#,
            "probe_value=$((probe_value+2)); printf '%s\\n' \"$probe_value\"",
            "false",
        ),
        CodeLanguage::TypeScript => (TYPESCRIPT, NODE_SECOND, NODE_ERROR),
        CodeLanguage::JavaScript => (JAVASCRIPT, NODE_SECOND, NODE_ERROR),
    }
}
const TYPESCRIPT: &str = r#"var ghFs=require("fs");
if (process.getuid()<20000 || process.getuid()>=20004 || process.getgid()!=1000 || !process.getgroups().every(group=>group===1000)) throw new Error("identity");
if (!ghFs.readFileSync("/proc/self/status","utf8").includes("CapEff:\t0000000000000000")) throw new Error("capabilities");
var probeValue: number=40;
ghFs.appendFileSync("/workspace/goldenhoop-probe-once","x"); console.log("kernel-start");"#;
const JAVASCRIPT: &str = r#"var ghFs=require("fs");
if (process.getuid()<20000 || process.getuid()>=20004 || process.getgid()!=1000 || !process.getgroups().every(group=>group===1000)) throw new Error("identity");
if (!ghFs.readFileSync("/proc/self/status","utf8").includes("CapEff:\t0000000000000000")) throw new Error("capabilities");
var probeValue=40;
ghFs.appendFileSync("/workspace/goldenhoop-probe-once","x"); console.log("kernel-start");"#;
const NODE_SECOND: &str = "probeValue+=2; console.log(probeValue);";
const NODE_ERROR: &str = "throw new Error(\"expected probe exception\");";
