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

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Welcome, {user?.username ?? "Guest"}</h1>
            <p className="text-gray-600">SSID: {user?.ssid ?? "Not available"}</p>
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
                <CardTitle>API Integration</CardTitle>
                <CardDescription>Authenticate your API requests using a custom header</CardDescription>
              </CardHeader>
              <CardContent>
                <div>
                  <label className="block text-sm font-medium mb-1">X-API-KEY</label>
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
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}