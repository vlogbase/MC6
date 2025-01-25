import { useUser } from "@/hooks/use-user";
import { useLinks } from "@/hooks/use-links";
import { useStrackrStats } from "@/hooks/use-strackr-stats";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LogOut, Copy, Loader2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useMemo, useEffect } from "react";

export default function Home() {
  const { toast } = useToast();
  const { user, logout } = useUser();
  const { links, isLoading: linksLoading } = useLinks();
  const { transactions, revenues, clicks, isLoading: statsLoading, error: statsError } = useStrackrStats();

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
      description: "API for rewriting affiliate links with custom tracking"
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
          security: [{ ApiKeyAuth: [] }],
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
              description: "Missing or invalid API key",
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
              description: "Source identifier for tracking"
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
        ApiKeyAuth: {
          type: "apiKey",
          in: "header",
          name: "X-API-KEY"
        }
      }
    }
  };

  const gptPrompt = `To use this API for rewriting URLs, include your API key in the X-API-KEY header:

1. Add the following header to all requests:
   X-API-KEY: ${user?.apiKey}

2. Make a POST request to ${window.location.origin}/api/rewrite with:
   - Content-Type: application/json
   - Body: {
       "url": "https://example.com/product",
       "source": "my-source"
     }

3. You'll receive a response with the rewritten URL:
   {
     "rewrittenUrl": "https://tracking.example.com/product?ssid=YOUR_SSID&source=my-source"
   }

4. Error responses will include a message:
   {
     "error": "Error description"
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
            <TabsTrigger value="integration">API Integration</TabsTrigger>
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

          <TabsContent value="integration">
            <Card>
              <CardHeader>
                <CardTitle>Your API Key</CardTitle>
                <CardDescription>
                  Use this key to authenticate your API requests
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">API Key (Custom Header)</label>
                    <div className="relative">
                      <pre className="p-4 bg-gray-100 rounded-lg overflow-x-auto">
                        {user?.apiKey || ''}
                      </pre>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="absolute top-2 right-2"
                        onClick={() => handleCopy(user?.apiKey || "", "API key copied!")}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-semibold mb-2">How to Use</h3>
                    <div className="bg-gray-100 rounded-lg p-4 space-y-2">
                      <p className="text-sm text-gray-700">Add this header to your API requests:</p>
                      <pre className="bg-gray-200 p-2 rounded">
                        X-API-KEY: {user?.apiKey}
                      </pre>
                      <p className="text-sm text-gray-700 mt-4">Example curl request:</p>
                      <pre className="bg-gray-200 p-2 rounded whitespace-pre-wrap">
                        {`curl -X POST "${window.location.origin}/api/rewrite" \\
  -H "X-API-KEY: ${user?.apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com", "source": "my-source"}'`}
                      </pre>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
        <Tabs defaultValue="spec" className="space-y-4">
          <TabsList>
            <TabsTrigger value="spec">Spec</TabsTrigger>
          </TabsList>

          <TabsContent value="spec" className="space-y-4">
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