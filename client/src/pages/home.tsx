import { useLinks } from "@/hooks/use-links";
import { useStrackrStats } from "@/hooks/use-strackr-stats";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Loader2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useQuery } from "@tanstack/react-query";

interface OAuthCredentials {
  client_id: string;
  client_secret: string;
  token_url: string;
  scopes: string[];
  token_exchange_method: "post";
}

export default function Home() {
  const { toast } = useToast();
  const { links, isLoading: linksLoading } = useLinks();
  const { transactions, revenues, clicks, isLoading: statsLoading, error: statsError } = useStrackrStats();
  const { data: oauthCredentials } = useQuery<OAuthCredentials>({
    queryKey: ["/api/oauth-credentials"],
  });

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
      description: "API for automatic link rewriting"
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
          security: [{ bearerAuth: [] }],
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
            "401": {
              description: "Invalid token",
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
              description: "The rewritten URL with affiliate parameters"
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
        bearerAuth: {
          type: "http",
          scheme: "bearer"
        }
      }
    }
  };

  const gptPrompt = `To use this API for rewriting URLs, follow these steps:

1. Get an access token by making a POST request to \`${window.location.origin}/api/auth\`:
   - Content-Type: application/json
   - Body: {
       "client_id": "${oauthCredentials?.client_id || ''}",
       "client_secret": "${oauthCredentials?.client_secret || ''}"
     }

2. Use the returned access_token in your requests.

Example:
\`\`\`javascript
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

// Use the token to rewrite URLs
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

The access token expires after 1 hour. If you receive a 401 error, simply request a new token using the same process.
No user authentication is required - the API handles everything automatically.`;

  if (statsError) {
    toast({
      variant: "destructive",
      title: "Error loading stats",
      description: statsError.message
    });
  }

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-6xl mx-auto space-y-8">
        <div>
          <h1 className="text-3xl font-bold">Link Rewriting API Documentation</h1>
          <p className="text-gray-600">Integration guide and API credentials</p>
        </div>

        <Tabs defaultValue="spec" className="space-y-4">
          <TabsList>
            <TabsTrigger value="spec">API Documentation</TabsTrigger>
            <TabsTrigger value="stats">Statistics</TabsTrigger>
          </TabsList>

          <TabsContent value="spec" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Authentication Credentials</CardTitle>
                <CardDescription>
                  Use these credentials to authenticate your API requests
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
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>OpenAPI Specification</CardTitle>
                <CardDescription>
                  Copy this OpenAPI specification to integrate with your applications
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
                <CardTitle>GPT Integration Guide</CardTitle>
                <CardDescription>
                  Add these instructions to your GPT's configuration
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
                  <div className="text-center p-8 text-gray-500">
                    Statistics will be available after your first rewritten link is used
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