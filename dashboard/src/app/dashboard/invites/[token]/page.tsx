"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { orgs as orgsApi } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { toast } from "sonner";
import { Building2, Loader2, CheckCircle2, XCircle } from "lucide-react";

export default function AcceptInvitePage() {
  const { token: inviteToken } = useParams<{ token: string }>();
  const { token: authToken } = useAuth();
  const router = useRouter();
  const [accepting, setAccepting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);

  const handleAccept = async () => {
    if (!authToken || !inviteToken) return;
    setAccepting(true);
    const { data, error: err } = await orgsApi.acceptInvite(authToken, inviteToken);
    setAccepting(false);
    if (err) {
      setError(err);
      toast.error(err);
    } else if (data) {
      setAccepted(true);
      toast.success(`Joined ${data.name}`);
      setTimeout(() => router.push("/dashboard"), 2000);
    }
  };

  if (accepted) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center py-12">
            <CheckCircle2 className="h-12 w-12 text-emerald-500 mb-4" />
            <h3 className="text-lg font-semibold">Invite accepted</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Redirecting to dashboard...
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center py-12">
            <XCircle className="h-12 w-12 text-destructive mb-4" />
            <h3 className="text-lg font-semibold">Unable to accept invite</h3>
            <p className="text-sm text-muted-foreground mt-1 text-center max-w-sm">
              {error}
            </p>
            <Button
              variant="outline"
              className="mt-4"
              onClick={() => router.push("/dashboard")}
            >
              Go to dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-[50vh]">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="rounded-full bg-muted p-4">
              <Building2 className="h-8 w-8 text-muted-foreground" />
            </div>
          </div>
          <CardTitle>Organization Invite</CardTitle>
          <CardDescription>
            You have been invited to join an organization.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center">
          <Button onClick={handleAccept} disabled={accepting}>
            {accepting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Accepting...
              </>
            ) : (
              "Accept invite"
            )}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
