import { useUser } from "@/hooks/use-user";
import { useLinks } from "@/hooks/use-links";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { DataTable } from "@/components/ui/table";
import { DownloadIcon, Link, LogOut } from "lucide-react";

const linkFormSchema = z.object({
  originalUrl: z.string().url(),
  source: z.string().min(1),
});

export default function Home() {
  const { toast } = useToast();
  const { user, logout } = useUser();
  const { links, createLink, isLoading } = useLinks();

  const form = useForm<z.infer<typeof linkFormSchema>>({
    resolver: zodResolver(linkFormSchema),
    defaultValues: {
      originalUrl: "",
      source: "",
    },
  });

  async function onSubmit(values: z.infer<typeof linkFormSchema>) {
    try {
      await createLink(values);
      form.reset();
      toast({
        title: "Success",
        description: "Link created successfully",
      });
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to create link",
      });
    }
  }

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
            <CardTitle>Create New Link</CardTitle>
            <CardDescription>
              Enter a URL to create a new affiliate link
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="originalUrl"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>URL</FormLabel>
                        <FormControl>
                          <Input placeholder="https://..." {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="source"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Source</FormLabel>
                        <FormControl>
                          <Input placeholder="e.g. website, email" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
                <Button type="submit">Create Link</Button>
              </form>
            </Form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Your Links</CardTitle>
            <CardDescription>
              View and manage your affiliate links
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
