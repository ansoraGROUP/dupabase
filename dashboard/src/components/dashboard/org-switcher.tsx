"use client";

import { useState } from "react";
import { useOrg } from "@/lib/org-context";
import { useAuth } from "@/lib/auth-context";
import { orgs as orgsApi } from "@/lib/api";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SidebarMenu, SidebarMenuItem, SidebarMenuButton } from "@/components/ui/sidebar";
import { Building2, Check, ChevronsUpDown, Plus, Loader2 } from "lucide-react";
import { toast } from "sonner";

export default function OrgSwitcher() {
  const { token } = useAuth();
  const { orgs, activeOrg, setActiveOrg, refreshOrgs } = useOrg();
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [creating, setCreating] = useState(false);

  const handleNameChange = (value: string) => {
    setName(value);
    setSlug(value.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, ""));
  };

  const handleCreate = async () => {
    if (!token || !name.trim() || !slug.trim()) return;
    setCreating(true);
    const { data, error } = await orgsApi.create(token, name.trim(), slug.trim());
    setCreating(false);
    if (error) {
      toast.error(error);
    } else if (data) {
      toast.success(`Organization "${data.name}" created`);
      setName("");
      setSlug("");
      setCreateOpen(false);
      await refreshOrgs();
      setActiveOrg(data);
    }
  };

  return (
    <>
      <SidebarMenu>
        <SidebarMenuItem>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <SidebarMenuButton size="lg">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-muted">
                  <Building2 className="h-4 w-4" />
                </div>
                <div className="flex flex-col gap-0.5 leading-none">
                  <span className="text-sm font-medium truncate max-w-[140px]">
                    {activeOrg?.name ?? "No organization"}
                  </span>
                  <span className="text-xs text-muted-foreground truncate max-w-[140px]">
                    {activeOrg ? (activeOrg.slug.startsWith("personal-") ? "Personal workspace" : activeOrg.slug) : "Select or create"}
                  </span>
                </div>
                <ChevronsUpDown className="ml-auto h-4 w-4" />
              </SidebarMenuButton>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56">
              {orgs.map((org) => (
                <DropdownMenuItem
                  key={org.id}
                  onClick={() => setActiveOrg(org)}
                >
                  <Building2 className="mr-2 h-4 w-4" />
                  <span className="truncate">{org.name}</span>
                  {activeOrg?.id === org.id && (
                    <Check className="ml-auto h-4 w-4" />
                  )}
                </DropdownMenuItem>
              ))}
              {orgs.length > 0 && <DropdownMenuSeparator />}
              <DropdownMenuItem onClick={() => setCreateOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Create organization
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </SidebarMenuItem>
      </SidebarMenu>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create organization</DialogTitle>
            <DialogDescription>
              Organizations let you collaborate with team members on shared projects.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="org-name">Name</Label>
              <Input
                id="org-name"
                placeholder="My Team"
                value={name}
                onChange={(e) => handleNameChange(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="org-slug">Slug</Label>
              <Input
                id="org-slug"
                placeholder="my-team"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                URL-friendly identifier. Auto-generated from name.
              </p>
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button
              onClick={handleCreate}
              disabled={creating || !name.trim() || !slug.trim()}
            >
              {creating ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Creating...
                </>
              ) : (
                "Create organization"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
