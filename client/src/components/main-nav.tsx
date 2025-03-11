import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/use-auth";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { LogOut, User, BarChart3, ChartBar } from "lucide-react";

export function MainNav() {
  const { user, logoutMutation } = useAuth();

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  return (
    <header className="border-b bg-background">
      <div className="container flex h-16 items-center px-4">
        <Link href="/" className="font-semibold text-lg">
          AI Product Scanner
        </Link>

        <nav className="flex items-center ml-6 space-x-4 lg:space-x-6">
          <Button asChild variant="ghost">
            <Link href="/" className="text-sm font-medium">
              Home
            </Link>
          </Button>
          <Button asChild variant="ghost">
            <Link href="/plugin-demo" className="text-sm font-medium">
              Plugin Demo
            </Link>
          </Button>
          <Button asChild variant="ghost">
            <Link href="/ggs-visualization" className="text-sm font-medium">
              <ChartBar className="h-4 w-4 mr-2" />
              GGS Data
            </Link>
          </Button>
        </nav>

        <div className="ml-auto flex items-center space-x-4">
          {user && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon">
                  <User className="h-5 w-5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem className="text-sm">
                  Signed in as <span className="font-medium ml-1">{user.username}</span>
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => window.location.href = '/profile'}>
                  <User className="mr-2 h-4 w-4" />
                  <span>Profile</span>
                </DropdownMenuItem>
                {user.role === 'admin' && (
                  <DropdownMenuItem onClick={() => window.location.href = '/admin'}>
                    <BarChart3 className="mr-2 h-4 w-4" />
                    <span>Admin Dashboard</span>
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleLogout}>
                  <LogOut className="mr-2 h-4 w-4" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
    </header>
  );
}