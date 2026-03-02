"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Check, ChevronLeft, ChevronRight, Trash2, X } from "lucide-react";

export interface DataGridProps {
  columns: string[];
  rows: unknown[][];
  total: number;
  page: number;
  perPage: number;
  loading: boolean;
  onPageChange: (page: number) => void;
  onCellEdit?: (
    rowIdx: number,
    colIdx: number,
    oldValue: unknown,
    newValue: string
  ) => Promise<void>;
  onDeleteRow?: (rowIdx: number) => Promise<void>;
  emptyMessage?: string;
}

export function DataGrid({
  columns,
  rows,
  total,
  page,
  perPage,
  loading,
  onPageChange,
  onCellEdit,
  onDeleteRow,
  emptyMessage = "No rows found",
}: DataGridProps) {
  const [editingCell, setEditingCell] = useState<{
    rowIdx: number;
    colIdx: number;
  } | null>(null);
  const [editValue, setEditValue] = useState("");

  const totalPages = Math.ceil(total / perPage) || 1;

  const startEdit = (rowIdx: number, colIdx: number) => {
    if (!onCellEdit) return;
    setEditingCell({ rowIdx, colIdx });
    const val = rows[rowIdx][colIdx];
    setEditValue(val === null ? "" : String(val));
  };

  const cancelEdit = () => {
    setEditingCell(null);
    setEditValue("");
  };

  const saveEdit = async () => {
    if (!editingCell || !onCellEdit) return;
    const oldValue = rows[editingCell.rowIdx][editingCell.colIdx];
    await onCellEdit(editingCell.rowIdx, editingCell.colIdx, oldValue, editValue);
    cancelEdit();
  };

  if (loading) {
    return (
      <div className="p-4 space-y-2">
        {[1, 2, 3, 4, 5].map((i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    );
  }

  return (
    <>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              {columns.map((col) => (
                <TableHead
                  key={col}
                  className="font-mono text-xs whitespace-nowrap"
                >
                  {col}
                </TableHead>
              ))}
              {onDeleteRow && <TableHead className="w-10" />}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row, rowIdx) => (
              <TableRow key={rowIdx}>
                {row.map((cell, colIdx) => (
                  <TableCell
                    key={colIdx}
                    className={`font-mono text-xs max-w-[200px] truncate ${
                      onCellEdit ? "cursor-pointer hover:bg-muted/50" : ""
                    }`}
                    onClick={() => startEdit(rowIdx, colIdx)}
                  >
                    {editingCell?.rowIdx === rowIdx &&
                    editingCell?.colIdx === colIdx ? (
                      <div className="flex items-center gap-1">
                        <Input
                          className="h-7 text-xs font-mono"
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") saveEdit();
                            if (e.key === "Escape") cancelEdit();
                          }}
                          autoFocus
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 shrink-0"
                          onClick={(e) => {
                            e.stopPropagation();
                            saveEdit();
                          }}
                        >
                          <Check className="h-3 w-3" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 shrink-0"
                          onClick={(e) => {
                            e.stopPropagation();
                            cancelEdit();
                          }}
                        >
                          <X className="h-3 w-3" />
                        </Button>
                      </div>
                    ) : cell === null ? (
                      <span className="text-muted-foreground italic">NULL</span>
                    ) : typeof cell === "object" ? (
                      JSON.stringify(cell)
                    ) : (
                      String(cell)
                    )}
                  </TableCell>
                ))}
                {onDeleteRow && (
                  <TableCell>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-destructive hover:text-destructive"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Delete Row</AlertDialogTitle>
                          <AlertDialogDescription>
                            Are you sure you want to delete this row? This action
                            cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            variant="destructive"
                            onClick={() => onDeleteRow(rowIdx)}
                          >
                            Delete
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </TableCell>
                )}
              </TableRow>
            ))}
            {rows.length === 0 && (
              <TableRow>
                <TableCell
                  colSpan={columns.length + (onDeleteRow ? 1 : 0)}
                  className="text-center text-muted-foreground py-8"
                >
                  {emptyMessage}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      {/* Pagination */}
      <div className="flex items-center justify-between px-4 py-3 border-t">
        <p className="text-xs text-muted-foreground">
          {total} row{total !== 1 ? "s" : ""} total - Page {page} of{" "}
          {totalPages}
        </p>
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </>
  );
}
