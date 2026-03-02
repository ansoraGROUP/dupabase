"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { Download, Loader2 } from "lucide-react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3333";

export function ExportSection({ projectId }: { projectId: string }) {
  const { token } = useAuth();
  const [format, setFormat] = useState<"custom" | "sql">("custom");
  const [exporting, setExporting] = useState(false);
  const [schemaOnly, setSchemaOnly] = useState(false);
  const [dataOnly, setDataOnly] = useState(false);
  const [excludeAuth, setExcludeAuth] = useState(false);
  const [inserts, setInserts] = useState(false);
  const [tables, setTables] = useState("");
  const [excludeTables, setExcludeTables] = useState("");
  const [compress, setCompress] = useState("0");

  const handleExport = async () => {
    if (!token) return;
    setExporting(true);

    try {
      const params = new URLSearchParams({ format });
      if (schemaOnly) params.set("schema_only", "true");
      if (dataOnly) params.set("data_only", "true");
      if (excludeAuth) params.set("exclude_auth", "true");
      if (inserts) params.set("inserts", "true");
      if (tables.trim()) params.set("tables", tables.trim());
      if (excludeTables.trim()) params.set("exclude_tables", excludeTables.trim());
      if (format === "sql" && compress !== "0") params.set("compress", compress);

      const res = await fetch(
        `${API_URL}/platform/projects/${projectId}/export?${params}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (!res.ok) {
        const json = await res.json().catch(() => null);
        toast.error(json?.error || `Export failed (${res.status})`);
        return;
      }

      const disposition = res.headers.get("Content-Disposition");
      const filenameMatch = disposition?.match(/filename="(.+)"/);
      const filename = filenameMatch?.[1] || `export.${format === "sql" ? "sql" : "dump"}`;

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      toast.success(`Downloaded ${filename}`);
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-end gap-4">
        <div className="space-y-2">
          <p className="text-sm font-medium">Format</p>
          <Select
            value={format}
            onValueChange={(v) => setFormat(v as "custom" | "sql")}
          >
            <SelectTrigger className="w-[200px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="custom">Custom (.dump)</SelectItem>
              <SelectItem value="sql">Plain SQL (.sql)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button onClick={handleExport} disabled={exporting}>
          {exporting ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Exporting...
            </>
          ) : (
            <>
              <Download className="mr-2 h-4 w-4" />
              Download
            </>
          )}
        </Button>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex items-center justify-between rounded-md border p-3">
          <Label htmlFor="schema-only" className="text-sm cursor-pointer">Schema only</Label>
          <Switch
            id="schema-only"
            checked={schemaOnly}
            onCheckedChange={(v) => {
              setSchemaOnly(v);
              if (v) setDataOnly(false);
            }}
          />
        </div>
        <div className="flex items-center justify-between rounded-md border p-3">
          <Label htmlFor="data-only" className="text-sm cursor-pointer">Data only</Label>
          <Switch
            id="data-only"
            checked={dataOnly}
            onCheckedChange={(v) => {
              setDataOnly(v);
              if (v) setSchemaOnly(false);
            }}
          />
        </div>
        <div className="flex items-center justify-between rounded-md border p-3">
          <Label htmlFor="exclude-auth" className="text-sm cursor-pointer">Exclude auth schema</Label>
          <Switch
            id="exclude-auth"
            checked={excludeAuth}
            onCheckedChange={setExcludeAuth}
          />
        </div>
        <div className="flex items-center justify-between rounded-md border p-3">
          <Label htmlFor="inserts" className="text-sm cursor-pointer">Use INSERT statements</Label>
          <Switch
            id="inserts"
            checked={inserts}
            onCheckedChange={setInserts}
          />
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="tables" className="text-sm">Tables to include (comma-separated)</Label>
          <Input
            id="tables"
            placeholder="e.g. users, orders"
            value={tables}
            onChange={(e) => setTables(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="exclude-tables" className="text-sm">Tables to exclude (comma-separated)</Label>
          <Input
            id="exclude-tables"
            placeholder="e.g. logs, temp_data"
            value={excludeTables}
            onChange={(e) => setExcludeTables(e.target.value)}
          />
        </div>
      </div>

      {format === "sql" && (
        <div className="space-y-2 max-w-[200px]">
          <Label htmlFor="compress" className="text-sm">Compression (0-9)</Label>
          <Select value={compress} onValueChange={setCompress}>
            <SelectTrigger id="compress">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {Array.from({ length: 10 }, (_, i) => (
                <SelectItem key={i} value={String(i)}>
                  {i === 0 ? "None" : `Level ${i}`}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
    </div>
  );
}
