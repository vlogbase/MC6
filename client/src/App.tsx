import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
// Removed import { useUser } from "@/hooks/use-user";
// Removed AuthPage import
import { Loader2 } from "lucide-react";

function Router() {
  // No user check – if you want a loading spinner, you could keep something minimal:
  // e.g. a "Loading..." state, or simply remove all that logic.

  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router />
      <Toaster />
    </QueryClientProvider>
  );
}

export default App;
