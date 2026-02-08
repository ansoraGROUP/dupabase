"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Eye, EyeOff } from "lucide-react";
import { CopyButton } from "./copy-button";

export function SecretField({
  label,
  value,
}: {
  label: string;
  value?: string;
}) {
  const [visible, setVisible] = useState(false);
  const safeValue = value || "";

  return (
    <div className="space-y-1.5">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2">
        <code className="flex-1 text-xs break-all font-mono">
          {visible ? safeValue : "\u2022".repeat(Math.min(safeValue.length, 40))}
        </code>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 shrink-0"
          onClick={() => setVisible(!visible)}
        >
          {visible ? (
            <EyeOff className="h-3.5 w-3.5" />
          ) : (
            <Eye className="h-3.5 w-3.5" />
          )}
        </Button>
        <CopyButton value={safeValue} className="h-7 w-7 shrink-0" />
      </div>
    </div>
  );
}
