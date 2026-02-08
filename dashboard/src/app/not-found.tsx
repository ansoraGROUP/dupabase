import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Database } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-4">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted">
        <Database className="h-8 w-8 text-muted-foreground" />
      </div>
      <h1 className="text-2xl font-bold">Page not found</h1>
      <p className="text-muted-foreground text-center max-w-md">
        The page you&apos;re looking for doesn&apos;t exist or has been moved.
      </p>
      <Button asChild>
        <Link href="/dashboard">Go to Dashboard</Link>
      </Button>
    </div>
  );
}
