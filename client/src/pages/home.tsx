import { useUser } from "@/hooks/use-user";
import { useLinks } from "@/hooks/use-links";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { DownloadIcon, LogOut } from "lucide-react";

export default function Home() {
  const { toast } = useToast();
  const { user, logout } = useUser();
  const { links, isLoading } = useLinks();

  async function handleLogout() {
    try {
      const result = await logout();
      if (!result.ok) {
        toast({
          variant: "destructive",
          title: "Error",
          description: result.message,
        });
        return;
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to logout",
      });
    }
  }

  async function downloadOpenApi() {
    try {
      const response = await fetch("/api/openapi", {
        credentials: "include",
      });
      const spec = await response.json();
      const blob = new Blob([JSON.stringify(spec, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "openapi.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to download OpenAPI spec",
      });
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Welcome, {user?.username}</h1>
            <p className="text-gray-600">Your SSID: {user?.ssid}</p>
          </div>
          <div className="flex gap-4">
            <Button onClick={downloadOpenApi} variant="outline">
              <DownloadIcon className="mr-2 h-4 w-4" />
              Download OpenAPI Spec
            </Button>
            <Button onClick={handleLogout} variant="ghost">
              <LogOut className="mr-2 h-4 w-4" />
              Logout
            </Button>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Your Links</CardTitle>
            <CardDescription>
              View your affiliate links and their performance
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div>Loading...</div>
            ) : (
              <div className="border rounded-lg">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-2 text-left">Original URL</th>
                      <th className="px-4 py-2 text-left">Rewritten URL</th>
                      <th className="px-4 py-2 text-left">Source</th>
                      <th className="px-4 py-2 text-left">Clicks</th>
                      <th className="px-4 py-2 text-left">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {links?.map((link) => (
                      <tr key={link.id} className="border-t">
                        <td className="px-4 py-2">{link.originalUrl}</td>
                        <td className="px-4 py-2">{link.rewrittenUrl}</td>
                        <td className="px-4 py-2">{link.source}</td>
                        <td className="px-4 py-2">{link.clicks}</td>
                        <td className="px-4 py-2">
                          {new Date(link.createdAt!).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}