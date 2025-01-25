import { useUser } from "@/hooks/use-user";
import { useLinks } from "@/hooks/use-links";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LogOut, Copy } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useQuery } from "@tanstack/react-query";

interface OAuthCredentials {
  client_id: string;
  client_secret: string;
  authorization_url: string;
  token_url: string;
  scopes: string[];
  token_exchange_method: "basic_auth" | "post";
}

export default function Home() {
  const { toast } = useToast();
  const { user, logout } = useUser();
  const { links, isLoading } = useLinks();
  const { data: oauthCredentials } = useQuery<OAuthCredentials>({
    queryKey: ["/api/oauth-credentials"],
  });

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

  async function copyToClipboard(text: string, successMessage: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: "Success",
        description: successMessage,
      });
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to copy to clipboard",
      });
    }
  }

  const openApiSpec = {
    openapi: "3.1.0",
    info: {
      title: "Link Rewriting API",
      version: "1.0.0",
      description: `API for rewriting links with SSID: ${user?.ssid ?? ''}`
    },
    servers: [
      {
        url: window.location.origin
      }
    ],
    paths: {
      "/api/rewrite": {
        post: {
          operationId: "rewriteUrl",
          summary: "Rewrite a URL with affiliate information",
          security: [{ cookieAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  $ref: "#/components/schemas/RewriteUrlRequest"
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Successfully rewritten URL",
              content: {
                "application/json": {
                  schema: {
                    $ref: "#/components/schemas/RewriteUrlResponse"
                  }
                }
              }
            },
            "400": {
              description: "Invalid input",
              content: {
                "application/json": {
                  schema: {
                    $ref: "#/components/schemas/ErrorResponse"
                  }
                }
              }
            },
            "401": {
              description: "Not authenticated",
              content: {
                "application/json": {
                  schema: {
                    $ref: "#/components/schemas/ErrorResponse"
                  }
                }
              }
            },
            "500": {
              description: "Server error",
              content: {
                "application/json": {
                  schema: {
                    $ref: "#/components/schemas/ErrorResponse"
                  }
                }
              }
            }
          }
        }
      }
    },
    components: {
      schemas: {
        RewriteUrlRequest: {
          type: "object",
          required: ["url", "source"],
          properties: {
            url: {
              type: "string",
              description: "The URL to rewrite"
            },
            source: {
              type: "string",
              description: "Source identifier"
            }
          }
        },
        RewriteUrlResponse: {
          type: "object",
          required: ["rewrittenUrl"],
          properties: {
            rewrittenUrl: {
              type: "string",
              description: "The rewritten URL with SSID and source parameters"
            }
          }
        },
        ErrorResponse: {
          type: "object",
          required: ["error"],
          properties: {
            error: {
              type: "string",
              description: "Error message"
            }
          }
        }
      },
      securitySchemes: {
        cookieAuth: {
          type: "apiKey",
          in: "cookie",
          name: "connect.sid"
        }
      }
    }
  };

  const gptPrompt = `To use this API for rewriting URLs, follow these authentication steps:

1. First, obtain an access token by making a POST request to \`${window.location.origin}/api/auth\` with:
   - Content-Type: application/json
   - Body: {
       "client_id": "${oauthCredentials?.client_id || ''}",
       "client_secret": "${oauthCredentials?.client_secret || ''}"
     }

2. From the response, extract the access_token.

3. For all subsequent requests to rewrite URLs, include:
   - Authorization: Bearer <your_access_token>
   - Content-Type: application/json

4. To rewrite a URL, make a POST request to \`${window.location.origin}/api/rewrite\` with:
   - Body: {
       "url": "original-url-here",
       "source": "source-identifier"
     }

Example flow:
\`\`\`javascript
// Step 1: Get access token
const authResponse = await fetch("${window.location.origin}/api/auth", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    client_id: "${oauthCredentials?.client_id || ''}",
    client_secret: "${oauthCredentials?.client_secret || ''}"
  })
});
const { access_token } = await authResponse.json();

// Step 2: Rewrite URL using the token
const rewriteResponse = await fetch("${window.location.origin}/api/rewrite", {
  method: "POST",
  headers: {
    "Authorization": \`Bearer \${access_token}\`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    url: "https://example.com/product",
    source: "gpt-assistant"
  })
});
const { rewrittenUrl } = await rewriteResponse.json();
\`\`\`

After obtaining the rewritten URL, you can use it in your response.

Important: The access token expires after 1 hour. If you receive a 401 error, obtain a new token using Step 1.`;

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Welcome, {user?.username || "Guest"}</h1>
            <p className="text-gray-600">Your SSID: {user?.ssid || "Not available"}</p>
          </div>
          <Button onClick={handleLogout} variant="ghost">
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </Button>
        </div>

        <Tabs defaultValue="spec" className="space-y-4">
          <TabsList>
            <TabsTrigger value="spec">Spec</TabsTrigger>
            <TabsTrigger value="stats">Stats</TabsTrigger>
          </TabsList>

          <TabsContent value="spec" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Authentication Credentials</CardTitle>
                <CardDescription>
                  Copy these credentials into the GPT's authentication configuration
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Client ID</label>
                    <div className="relative">
                      <pre className="p-4 bg-gray-100 rounded-lg overflow-x-auto">
                        {oauthCredentials?.client_id || ''}
                      </pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute top-2 right-2"
                        onClick={() => copyToClipboard(oauthCredentials?.client_id || "", "Client ID copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Client Secret</label>
                    <div className="relative">
                      <pre className="p-4 bg-gray-100 rounded-lg overflow-x-auto">
                        {oauthCredentials?.client_secret || ''}
                      </pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute top-2 right-2"
                        onClick={() => copyToClipboard(oauthCredentials?.client_secret || "", "Client Secret copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Authorization URL</label>
                    <div className="relative">
                      <pre className="p-4 bg-gray-100 rounded-lg overflow-x-auto">
                        {oauthCredentials?.authorization_url || ''}
                      </pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute top-2 right-2"
                        onClick={() => copyToClipboard(oauthCredentials?.authorization_url || "", "Authorization URL copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Token URL</label>
                    <div className="relative">
                      <pre className="p-4 bg-gray-100 rounded-lg overflow-x-auto">
                        {oauthCredentials?.token_url || ''}
                      </pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute top-2 right-2"
                        onClick={() => copyToClipboard(oauthCredentials?.token_url || "", "Token URL copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Scope</label>
                    <div className="relative">
                      <pre className="p-4 bg-gray-100 rounded-lg overflow-x-auto">
                        {oauthCredentials?.scopes?.join(" ") || ''}
                      </pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute top-2 right-2"
                        onClick={() => copyToClipboard(oauthCredentials?.scopes?.join(" ") || "", "Scopes copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Token Exchange Method</label>
                    <div className="p-4 bg-gray-100 rounded-lg">
                      <p className="text-sm text-gray-700">
                        {oauthCredentials?.token_exchange_method === "basic_auth"
                          ? "Basic authorization header"
                          : "Default (POST request)"}
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>OpenAPI Specification</CardTitle>
                <CardDescription>
                  Copy your API specification to integrate with your applications
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="relative">
                  <pre className="p-4 bg-gray-100 rounded-lg overflow-x-auto">
                    {JSON.stringify(openApiSpec, null, 2)}
                  </pre>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(JSON.stringify(openApiSpec, null, 2), "OpenAPI spec copied!")}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>GPT Prompt</CardTitle>
                <CardDescription>
                  Instructions to add to your GPT prompt for automatic link rewriting
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="relative">
                  <pre className="p-4 bg-gray-100 rounded-lg whitespace-pre-wrap">
                    {gptPrompt}
                  </pre>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(gptPrompt, "GPT prompt copied!")}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="stats">
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
                          <th className="px-4 py-2 text-left">Created</th>
                        </tr>
                      </thead>
                      <tbody>
                        {links?.map((link) => (
                          <tr key={link.id} className="border-t">
                            <td className="px-4 py-2">{link.originalUrl}</td>
                            <td className="px-4 py-2">{link.rewrittenUrl}</td>
                            <td className="px-4 py-2">{link.source}</td>
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
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}