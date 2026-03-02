"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
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

  const handleExport = async () => {
    if (!token) return;
    setExporting(true);

    try {
      const res = await fetch(
        `${API_URL}/platform/projects/${projectId}/export?format=${format}`,
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
  );
}
