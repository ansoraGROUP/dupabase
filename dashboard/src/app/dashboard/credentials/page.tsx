"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { credentials as credentialsApi } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { KeyRound, Loader2, Eye, EyeOff } from "lucide-react";
import { CopyButton } from "@/components/dashboard/copy-button";

export default function CredentialsPage() {
  const { token, user, loading: authLoading } = useAuth();
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [revealed, setRevealed] = useState<{
    pg_username: string;
    pg_password: string;
  } | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  const handleReveal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !password) return;
    setLoading(true);
    const { data, error } = await credentialsApi.reveal(token, password);
    setLoading(false);
    if (error) {
      toast.error(error);
    } else if (data) {
      setRevealed(data);
      setPassword("");
      toast.success("Credentials revealed");
    }
  };

  if (authLoading) {
    return (
      <div className="space-y-6">
        <div>
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-4 w-80 mt-2" />
        </div>
        {[1, 2].map((i) => (
          <div key={i}>
            {i > 1 && <Separator className="my-6" />}
            <div className="grid grid-cols-1 md:grid-cols-[280px_1fr] gap-6 md:gap-8">
              <div className="space-y-1.5">
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-4 w-48" />
              </div>
              <Card>
                <CardContent className="pt-6 space-y-4">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                </CardContent>
              </Card>
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">
          PostgreSQL Credentials
        </h2>
        <p className="text-muted-foreground">
          Your single PostgreSQL username and password for all your databases
        </p>
      </div>

      {/* Username Section */}
      <div className="grid grid-cols-1 md:grid-cols-[280px_1fr] gap-6 md:gap-8">
        <div className="space-y-1.5">
          <h3 className="text-sm font-medium">PostgreSQL Username</h3>
          <p className="text-sm text-muted-foreground">
            Auto-generated when you registered. Gives you access to all your project databases.
          </p>
        </div>
        <Card>
          <CardContent className="pt-6 space-y-3">
            <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2">
              <code className="flex-1 text-sm font-mono">
                {user?.pg_username || "\u2014"}
              </code>
              {user?.pg_username && (
                <CopyButton
                  value={user.pg_username}
                  className="h-7 w-7 shrink-0"
                />
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Use this username with your PG password to connect via psql or any PostgreSQL client.
            </p>
          </CardContent>
        </Card>
      </div>

      <Separator />

      {/* Password Section */}
      <div className="grid grid-cols-1 md:grid-cols-[280px_1fr] gap-6 md:gap-8">
        <div className="space-y-1.5">
          <h3 className="text-sm font-medium">Reveal Password</h3>
          <p className="text-sm text-muted-foreground">
            Enter your platform password to decrypt and reveal your PostgreSQL password.
          </p>
        </div>
        <Card>
          <CardContent className="pt-6">
            {revealed ? (
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">
                    PG Username
                  </Label>
                  <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2">
                    <code className="flex-1 text-sm font-mono">
                      {revealed.pg_username}
                    </code>
                    <CopyButton
                      value={revealed.pg_username}
                      className="h-7 w-7 shrink-0"
                    />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">
                    PG Password
                  </Label>
                  <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2">
                    <code className="flex-1 text-sm font-mono break-all">
                      {showPassword
                        ? revealed.pg_password
                        : "\u2022".repeat(20)}
                    </code>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 shrink-0"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <EyeOff className="h-3.5 w-3.5" />
                      ) : (
                        <Eye className="h-3.5 w-3.5" />
                      )}
                    </Button>
                    <CopyButton
                      value={revealed.pg_password}
                      className="h-7 w-7 shrink-0"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setRevealed(null);
                      setShowPassword(false);
                    }}
                  >
                    Hide credentials
                  </Button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleReveal} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="platform-password">Platform password</Label>
                  <Input
                    id="platform-password"
                    type="password"
                    placeholder="Enter your platform password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
                <div className="flex justify-end">
                  <Button type="submit" disabled={loading || !password}>
                    {loading ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Decrypting...
                      </>
                    ) : (
                      <>
                        <KeyRound className="mr-2 h-4 w-4" />
                        Reveal password
                      </>
                    )}
                  </Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
