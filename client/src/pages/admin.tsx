import { useEffect, useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useLocation } from "wouter";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2, Users, Package2 } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { type User } from "@shared/schema";

type UserWithStats = User & {
  productsCount: number;
};

export default function AdminDashboard() {
  const { user } = useAuth();
  const [_, setLocation] = useLocation();
  const [users, setUsers] = useState<UserWithStats[]>([]);
  const [userCount, setUserCount] = useState(0);
  const [productCount, setProductCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    // Redirect if not admin
    if (user && user.role !== 'admin') {
      setLocation('/');
      return;
    }
  }, [user, setLocation]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, usersRes] = await Promise.all([
          apiRequest('GET', '/api/admin/stats'),
          apiRequest('GET', '/api/admin/users')
        ]);

        const statsData = await statsRes.json();
        const usersData = await usersRes.json();

        setUserCount(statsData.userCount);
        setProductCount(statsData.productCount);
        setUsers(usersData);
        setIsLoading(false);
      } catch (error) {
        console.error("Failed to fetch admin data:", error);
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleRoleChange = async (userId: number, newRole: string) => {
    try {
      await apiRequest('PUT', `/api/admin/users/${userId}/role`, { role: newRole });

      // Update local state
      setUsers(users.map(u => 
        u.id === userId ? { ...u, role: newRole } : u
      ));

      toast({
        title: "Role updated",
        description: "User role has been successfully updated",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update user role",
        variant: "destructive",
      });
    }
  };

  if (isLoading) {
    return (
      <div className="container py-8 flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container py-8">
      <h1 className="text-4xl font-bold mb-8">Admin Dashboard</h1>

      <div className="grid gap-6 md:grid-cols-2 mb-8">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{userCount}</div>
            <p className="text-xs text-muted-foreground">
              Registered user accounts
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Products</CardTitle>
            <Package2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{productCount}</div>
            <p className="text-xs text-muted-foreground">
              Products identified across all users
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
          <CardDescription>Manage user roles and view their activity</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Products Scanned</TableHead>
                <TableHead>Created At</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>{user.username}</TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>{user.role}</TableCell>
                  <TableCell>{user.productsCount}</TableCell>
                  <TableCell>{new Date(user.createdAt).toLocaleDateString()}</TableCell>
                  <TableCell>
                    <Select
                      defaultValue={user.role}
                      onValueChange={(value) => handleRoleChange(user.id, value)}
                    >
                      <SelectTrigger className="w-[120px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="user">User</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                      </SelectContent>
                    </Select>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}