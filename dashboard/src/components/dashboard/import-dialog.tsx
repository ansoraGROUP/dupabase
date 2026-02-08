"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { imports, type ImportTask } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import {
  Upload,
  FileUp,
  CheckCircle2,
  XCircle,
  Loader2,
  Info,
  X,
} from "lucide-react";

const ACCEPTED_EXTENSIONS = [".sql", ".dump", ".backup", ".tar"];
const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB

interface ImportDialogProps {
  projectId: string;
  onComplete?: () => void;
}

export function ImportDialog({ projectId, onComplete }: ImportDialogProps) {
  const { token } = useAuth();
  const [open, setOpen] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [activeTask, setActiveTask] = useState<ImportTask | null>(null);
  const [cleanImport, setCleanImport] = useState(false);
  const [skipAuth, setSkipAuth] = useState(true);
  const [disableTriggers, setDisableTriggers] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const resetState = useCallback(() => {
    setFile(null);
    setUploading(false);
    setActiveTask(null);
    setCleanImport(false);
    setSkipAuth(true);
    setDisableTriggers(true);
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  // Poll for status
  useEffect(() => {
    if (!activeTask || !token) return;
    if (activeTask.status !== "running" && activeTask.status !== "uploading") return;

    pollRef.current = setInterval(async () => {
      const { data, error } = await imports.status(token, projectId, activeTask.id);
      if (error) return;
      if (data) {
        setActiveTask(data);
        if (data.status === "completed" || data.status === "failed" || data.status === "cancelled") {
          if (pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
          }
          if (data.status === "completed") {
            toast.success(`Import completed! ${data.tables_imported ?? 0} tables imported.`);
            onComplete?.();
          } else if (data.status === "failed") {
            toast.error(`Import failed: ${data.error_message}`);
          }
        }
      }
    }, 2000);

    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [activeTask?.id, activeTask?.status, token, projectId, onComplete]);

  const validateFile = (f: File): string | null => {
    const ext = f.name.slice(f.name.lastIndexOf(".")).toLowerCase();
    if (!ACCEPTED_EXTENSIONS.includes(ext)) {
      return `Unsupported file type. Use ${ACCEPTED_EXTENSIONS.join(", ")}`;
    }
    if (f.size > MAX_FILE_SIZE) {
      return `File too large. Maximum size is 500MB.`;
    }
    return null;
  };

  const handleFile = (f: File) => {
    const err = validateFile(f);
    if (err) {
      toast.error(err);
      return;
    }
    setFile(f);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  };

  const handleStartImport = async () => {
    if (!file || !token) return;
    setUploading(true);

    const { data, error } = await imports.start(token, projectId, file, {
      clean_import: cleanImport,
      skip_auth_schema: skipAuth,
      disable_triggers: disableTriggers,
    });

    if (error) {
      toast.error(error);
      setUploading(false);
      return;
    }

    if (data) {
      setActiveTask(data);
      setUploading(false);
    }
  };

  const handleCancel = async () => {
    if (!activeTask || !token) return;
    await imports.cancel(token, projectId, activeTask.id);
    resetState();
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const isRunning = activeTask?.status === "running" || activeTask?.status === "uploading";
  const isDone = activeTask?.status === "completed";
  const isFailed = activeTask?.status === "failed";

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!isRunning) {
          setOpen(v);
          if (!v) resetState();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <Upload className="mr-2 h-4 w-4" />
          Import Database
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Import Database</DialogTitle>
          <DialogDescription>
            Upload a pg_dump file or SQL script to restore into this project.
          </DialogDescription>
        </DialogHeader>

        {!activeTask && !uploading && (
          <div className="space-y-4">
            {/* Drop zone */}
            <div
              className={`relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 transition-colors cursor-pointer ${
                dragOver
                  ? "border-primary bg-primary/5"
                  : file
                    ? "border-green-500/50 bg-green-500/5"
                    : "border-muted-foreground/25 hover:border-muted-foreground/50"
              }`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".sql,.dump,.backup,.tar"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFile(f);
                }}
              />
              {file ? (
                <div className="flex items-center gap-3">
                  <FileUp className="h-8 w-8 text-green-500" />
                  <div>
                    <p className="text-sm font-medium">{file.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatSize(file.size)}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6"
                    onClick={(e) => {
                      e.stopPropagation();
                      setFile(null);
                    }}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ) : (
                <>
                  <Upload className="h-8 w-8 text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">
                    Drop your file here or click to browse
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    .sql, .dump, .backup, .tar (max 500MB)
                  </p>
                </>
              )}
            </div>

            {/* Options */}
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="skip-auth"
                  checked={skipAuth}
                  onCheckedChange={(c) => setSkipAuth(!!c)}
                />
                <Label htmlFor="skip-auth" className="text-sm">
                  Skip auth schema (recommended)
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="disable-triggers"
                  checked={disableTriggers}
                  onCheckedChange={(c) => setDisableTriggers(!!c)}
                />
                <Label htmlFor="disable-triggers" className="text-sm">
                  Disable triggers during import
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="clean-import"
                  checked={cleanImport}
                  onCheckedChange={(c) => setCleanImport(!!c)}
                />
                <Label htmlFor="clean-import" className="text-sm text-destructive">
                  Clean import (drops existing public tables)
                </Label>
              </div>
            </div>

            {/* Best practices tip */}
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription className="text-xs">
                For best results, export from Supabase with:{" "}
                <code className="bg-muted px-1 py-0.5 rounded text-xs">
                  pg_dump --no-owner --no-acl --format=custom your_db
                </code>
              </AlertDescription>
            </Alert>

            <Button
              className="w-full"
              disabled={!file}
              onClick={handleStartImport}
            >
              <Upload className="mr-2 h-4 w-4" />
              Start Import
            </Button>
          </div>
        )}

        {/* Uploading state */}
        {uploading && (
          <div className="flex flex-col items-center gap-3 py-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">Uploading file...</p>
          </div>
        )}

        {/* Running state */}
        {isRunning && !uploading && (
          <div className="space-y-4 py-4">
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <p className="text-sm font-medium">Importing database...</p>
              <p className="text-xs text-muted-foreground">
                {activeTask.file_name} ({formatSize(activeTask.file_size)})
              </p>
            </div>
            <Progress value={undefined} className="animate-pulse" />
            <div className="flex justify-center">
              <Button variant="outline" size="sm" onClick={handleCancel}>
                Cancel Import
              </Button>
            </div>
          </div>
        )}

        {/* Completed state */}
        {isDone && (
          <div className="space-y-4 py-4">
            <div className="flex flex-col items-center gap-3">
              <CheckCircle2 className="h-10 w-10 text-green-500" />
              <p className="text-sm font-medium">Import completed!</p>
              <Badge variant="secondary">
                {activeTask.tables_imported ?? 0} tables imported
              </Badge>
            </div>
            <Button className="w-full" onClick={() => { setOpen(false); resetState(); }}>
              Done
            </Button>
          </div>
        )}

        {/* Failed state */}
        {isFailed && (
          <div className="space-y-4 py-4">
            <div className="flex flex-col items-center gap-3">
              <XCircle className="h-10 w-10 text-destructive" />
              <p className="text-sm font-medium">Import failed</p>
              <p className="text-xs text-muted-foreground text-center max-w-sm">
                {activeTask.error_message}
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                className="flex-1"
                onClick={() => { setOpen(false); resetState(); }}
              >
                Close
              </Button>
              <Button className="flex-1" onClick={resetState}>
                Try Again
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
