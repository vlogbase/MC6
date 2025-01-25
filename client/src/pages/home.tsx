import { useUser } from "@/hooks/use-user";
import { useLinks } from "@/hooks/use-links";
import { useStrackrStats } from "@/hooks/use-strackr-stats";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LogOut, Copy, Loader2 } from "lucide-react";
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
  const { links, isLoading: linksLoading } = useLinks();
  const { transactions, revenues, clicks, isLoading: statsLoading, error: statsError } = useStrackrStats();
  const { data: oauthCredentials } = useQuery<OAuthCredentials>({
    queryKey: ["/api/oauth-credentials"],
  });

  async function handleLogout() {
    try {
      await logout();
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

  const gptPrompt = `To use this API for rewriting URLs, follow these steps:

1. First, obtain an access token by making a POST request to \`${window.location.origin}/api/auth\`:
   Headers:
   - Content-Type: application/json

   Body:
   {
     "client_id": "${oauthCredentials?.client_id || ''}",
     "client_secret": "${oauthCredentials?.client_secret || ''}"
   }

2. Use the received access_token in the Authorization header for all rewrite requests:
   Headers:
   - Authorization: Bearer <access_token>
   - Content-Type: application/json

3. Make rewrite requests to \`${window.location.origin}/api/rewrite\`:
   Body:
   {
     "url": "original-url-here",
     "source": "source-identifier"
   }

Example code:
\`\`\`javascript
async function getRewrittenUrl(originalUrl) {
  // Get access token
  const authResponse = await fetch("${window.location.origin}/api/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: "${oauthCredentials?.client_id || ''}",
      client_secret: "${oauthCredentials?.client_secret || ''}"
    })
  });
  const { access_token } = await authResponse.json();

  // Rewrite URL
  const rewriteResponse = await fetch("${window.location.origin}/api/rewrite", {
    method: "POST",
    headers: {
      "Authorization": \`Bearer \${access_token}\`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      url: originalUrl,
      source: "gpt-assistant"
    })
  });
  const { rewrittenUrl } = await rewriteResponse.json();
  return rewrittenUrl;
}
\`\`\`

Note: Access tokens expire after 1 hour. If you receive a 401 error, obtain a new token using step 1.`;

  if (statsError) {
    toast({
      variant: "destructive",
      title: "Error loading stats",
      description: statsError.message
    });
  }

  // Calculate summary statistics
  const transactionStats = {
    total: transactions?.length || 0,
    totalAmount: transactions?.reduce((sum, t) => sum + parseFloat(t.price), 0) || 0,
    pendingCount: transactions?.filter(t => t.status_id === 'pending').length || 0
  };

  const revenueStats = {
    total: revenues?.reduce((sum, r) => sum + parseFloat(r.revenue), 0) || 0,
    transactionCount: revenues?.reduce((sum, r) => sum + (r.transactions || 0), 0) || 0,
    currency: revenues?.[0]?.currency || 'USD'
  };

  const clickStats = {
    total: clicks?.reduce((sum, c) => sum + (c.clicks || 0), 0) || 0,
    channels: [...new Set(clicks?.map(c => c.channel_name) || [])].length
  };

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
                <CardTitle>OAuth Credentials</CardTitle>
                <CardDescription>
                  API credentials for automatic link rewriting via OAuth
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
                <CardTitle>GPT Integration Instructions</CardTitle>
                <CardDescription>
                  Add these instructions to your GPT for automatic OAuth authentication and link rewriting
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
                    onClick={() => copyToClipboard(gptPrompt, "GPT instructions copied!")}
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
                <CardTitle>Performance Statistics</CardTitle>
                <CardDescription>
                  View your affiliate performance metrics
                </CardDescription>
              </CardHeader>
              <CardContent>
                {statsLoading ? (
                  <div className="flex justify-center items-center p-8">
                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                  </div>
                ) : (
                  <Tabs defaultValue="transactions" className="space-y-4">
                    <TabsList>
                      <TabsTrigger value="transactions">Transactions</TabsTrigger>
                      <TabsTrigger value="revenue">Revenue</TabsTrigger>
                      <TabsTrigger value="clicks">Clicks</TabsTrigger>
                    </TabsList>

                    <TabsContent value="transactions">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">{transactionStats.total}</div>
                            <p className="text-sm text-muted-foreground">Total Transactions</p>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">
                              {transactions?.[0]?.currency} {transactionStats.totalAmount.toFixed(2)}
                            </div>
                            <p className="text-sm text-muted-foreground">Total Transaction Value</p>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">{transactionStats.pendingCount}</div>
                            <p className="text-sm text-muted-foreground">Pending Transactions</p>
                          </CardContent>
                        </Card>
                      </div>
                      <div className="border rounded-lg overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50">
                            <tr>
                              <th className="px-4 py-2 text-left">Date</th>
                              <th className="px-4 py-2 text-left">Advertiser</th>
                              <th className="px-4 py-2 text-left">Order ID</th>
                              <th className="px-4 py-2 text-left">Amount</th>
                              <th className="px-4 py-2 text-left">Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {transactions?.map((transaction: any) => (
                              <tr key={transaction.id} className="border-t">
                                <td className="px-4 py-2">
                                  {new Date(transaction.sold).toLocaleDateString()}
                                </td>
                                <td className="px-4 py-2">{transaction.advertiser_name}</td>
                                <td className="px-4 py-2">{transaction.order_id}</td>
                                <td className="px-4 py-2">
                                  {transaction.currency} {transaction.price}
                                </td>
                                <td className="px-4 py-2">{transaction.status_name}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </TabsContent>

                    <TabsContent value="revenue">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">
                              {revenueStats.currency} {revenueStats.total.toFixed(2)}
                            </div>
                            <p className="text-sm text-muted-foreground">Total Revenue</p>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">{revenueStats.transactionCount}</div>
                            <p className="text-sm text-muted-foreground">Total Transactions</p>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">
                              {revenueStats.total > 0 && revenueStats.transactionCount > 0
                                ? `${revenueStats.currency} ${(revenueStats.total / revenueStats.transactionCount).toFixed(2)}`
                                : '-'}
                            </div>
                            <p className="text-sm text-muted-foreground">Average Revenue per Transaction</p>
                          </CardContent>
                        </Card>
                      </div>
                      <div className="border rounded-lg overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50">
                            <tr>
                              <th className="px-4 py-2 text-left">Date</th>
                              <th className="px-4 py-2 text-left">Advertiser</th>
                              <th className="px-4 py-2 text-left">Revenue</th>
                              <th className="px-4 py-2 text-left">Status</th>
                              <th className="px-4 py-2 text-left">Transactions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {revenues?.map((revenue: any) => (
                              <tr key={`${revenue.day}-${revenue.advertiser_id}`} className="border-t">
                                <td className="px-4 py-2">
                                  {new Date(revenue.day).toLocaleDateString()}
                                </td>
                                <td className="px-4 py-2">{revenue.advertiser_name}</td>
                                <td className="px-4 py-2">
                                  {revenue.currency} {revenue.revenue}
                                </td>
                                <td className="px-4 py-2">{revenue.status_name}</td>
                                <td className="px-4 py-2">{revenue.transactions}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </TabsContent>

                    <TabsContent value="clicks">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">{clickStats.total}</div>
                            <p className="text-sm text-muted-foreground">Total Clicks</p>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="pt-6">
                            <div className="text-2xl font-bold">{clickStats.channels}</div>
                            <p className="text-sm text-muted-foreground">Active Channels</p>
                          </CardContent>
                        </Card>
                      </div>
                      <div className="border rounded-lg overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50">
                            <tr>
                              <th className="px-4 py-2 text-left">Date</th>
                              <th className="px-4 py-2 text-left">Advertiser</th>
                              <th className="px-4 py-2 text-left">Clicks</th>
                              <th className="px-4 py-2 text-left">Channel</th>
                            </tr>
                          </thead>
                          <tbody>
                            {clicks?.map((click: any) => (
                              <tr key={`${click.day}-${click.advertiser_id}`} className="border-t">
                                <td className="px-4 py-2">
                                  {new Date(click.day).toLocaleDateString()}
                                </td>
                                <td className="px-4 py-2">{click.advertiser_name}</td>
                                <td className="px-4 py-2">{click.clicks}</td>
                                <td className="px-4 py-2">{click.channel_name}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </TabsContent>
                  </Tabs>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}