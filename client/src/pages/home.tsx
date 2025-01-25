import { useUser } from "@/hooks/use-user";
import { useLinks } from "@/hooks/use-links";
import { useStrackrStats } from "@/hooks/use-strackr-stats";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LogOut, Copy, Loader2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useEffect } from "react";

interface OAuthCredentials {
  client_id: string;
  client_secret: string;
  token_url: string;
  scopes: string[];
  authorization_url?: string;
  token_exchange_method?: string;
}

export default function Home() {
  const { toast } = useToast();
  const { user, logout } = useUser();
  const { links, isLoading: linksLoading } = useLinks();
  const { transactions, revenues, clicks, isLoading: statsLoading, error: statsError } = useStrackrStats();
  const { data: oauthCredentials } = useQuery<OAuthCredentials>({
    queryKey: ["/api/oauth-credentials"],
  });

  // Memoize stats calculations
  const stats = useMemo(() => ({
    transactions: {
      total: transactions?.length ?? 0,
      totalAmount: transactions?.reduce((sum, t) => sum + parseFloat(t.price), 0) ?? 0,
      pendingCount: transactions?.filter(t => t.status_id === 'pending').length ?? 0
    },
    revenue: {
      total: revenues?.reduce((sum, r) => sum + parseFloat(r.revenue), 0) ?? 0,
      transactionCount: revenues?.reduce((sum, r) => sum + (r.transactions || 0), 0) ?? 0,
      currency: revenues?.[0]?.currency ?? 'USD'
    },
    clicks: {
      total: clicks?.reduce((sum, c) => sum + (c.clicks || 0), 0) ?? 0,
      channels: clicks ? new Set(clicks.map(c => c.channel_name)).size : 0
    }
  }), [transactions, revenues, clicks]);

  // Handle logout
  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to logout",
      });
    }
  };

  // Handle stats error
  useEffect(() => {
    if (statsError) {
      toast({
        variant: "destructive",
        title: "Error loading stats",
        description: statsError.message
      });
    }
  }, [statsError, toast]);

  // Handle copy to clipboard
  const handleCopy = async (text: string, successMessage: string) => {
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
  };

  if (statsLoading || linksLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  const openApiSpec = {
    openapi: "3.1.0",
    info: {
      title: "Link Rewriting API",
      version: "1.0.0",
      description: "API for rewriting links"
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

1. First, obtain an access token by making a POST request to ${window.location.origin}/api/auth with:
   - Content-Type: application/json
   - Body: {
       "client_id": "${oauthCredentials?.client_id ?? ''}",
       "client_secret": "${oauthCredentials?.client_secret ?? ''}"
     }

2. From the response, extract the access_token.

3. For all subsequent requests to rewrite URLs, include:
   - Authorization: Bearer <your_access_token>
   - Content-Type: application/json

4. To rewrite a URL, make a POST request to ${window.location.origin}/api/rewrite with:
   - Body: {
       "url": "original-url-here",
       "source": "source-identifier"
     }`;

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Welcome, {user?.username ?? "Guest"}</h1>
            <p className="text-gray-600">User ID: {user?.id ?? "Not available"}</p>
          </div>
          <Button onClick={handleLogout} variant="ghost">
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </Button>
        </div>

        <Tabs defaultValue="stats" className="space-y-4">
          <TabsList>
            <TabsTrigger value="stats">Stats</TabsTrigger>
            <TabsTrigger value="links">Links</TabsTrigger>
          </TabsList>

          <TabsContent value="stats">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Transactions</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-2xl font-bold">{stats.transactions.total}</p>
                  <p className="text-sm text-gray-600">Total Amount: {stats.transactions.totalAmount}</p>
                  <p className="text-sm text-gray-600">Pending: {stats.transactions.pendingCount}</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Revenue</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-2xl font-bold">{stats.revenue.currency} {stats.revenue.total}</p>
                  <p className="text-sm text-gray-600">Transactions: {stats.revenue.transactionCount}</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Clicks</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-2xl font-bold">{stats.clicks.total}</p>
                  <p className="text-sm text-gray-600">Active Channels: {stats.clicks.channels}</p>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="links">
            {oauthCredentials && (
              <Card>
                <CardHeader>
                  <CardTitle>OAuth Credentials</CardTitle>
                  <CardDescription>Your API access credentials</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="text-sm font-medium">Client ID</label>
                    <div className="mt-1 relative">
                      <pre className="p-2 bg-gray-100 rounded">{oauthCredentials.client_id}</pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute right-2 top-2"
                        onClick={() => handleCopy(oauthCredentials.client_id, "Client ID copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium">Client Secret</label>
                    <div className="mt-1 relative">
                      <pre className="p-2 bg-gray-100 rounded">{oauthCredentials.client_secret}</pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute right-2 top-2"
                        onClick={() => handleCopy(oauthCredentials.client_secret, "Client Secret copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
        <Tabs defaultValue="spec" className="space-y-4">
          <TabsList>
            <TabsTrigger value="spec">Spec</TabsTrigger>
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
                        onClick={() => handleCopy(oauthCredentials?.client_id || "", "Client ID copied!")}
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
                        onClick={() => handleCopy(oauthCredentials?.client_secret || "", "Client Secret copied!")}
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
                        onClick={() => handleCopy(oauthCredentials?.authorization_url || "", "Authorization URL copied!")}
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
                        onClick={() => handleCopy(oauthCredentials?.token_url || "", "Token URL copied!")}
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
                        onClick={() => handleCopy(oauthCredentials?.scopes?.join(" ") || "", "Scopes copied!")}
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
                    onClick={() => handleCopy(JSON.stringify(openApiSpec, null, 2), "OpenAPI spec copied!")}
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
                    onClick={() => handleCopy(gptPrompt, "GPT prompt copied!")}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}