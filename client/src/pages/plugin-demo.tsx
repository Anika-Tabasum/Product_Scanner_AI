import { useState } from 'react';
import { Link } from 'wouter';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { ProductCard } from '@/components/product-card';
import { useQuery } from '@tanstack/react-query';
import { type Product } from '@shared/schema';
import { ArrowLeft, Search } from 'lucide-react';

export default function PluginDemo() {
  const [search, setSearch] = useState('');

  const { data: products } = useQuery<Product[]>({
    queryKey: ['/api/products/search', search],
    enabled: search.length > 0
  });

  return (
    <div className="container mx-auto py-8 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <Button asChild variant="ghost" size="icon">
            <Link href="/">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <h1 className="text-2xl font-bold">Plugin Demo</h1>
        </div>

        <div className="bg-card p-6 rounded-lg border mb-8">
          <h2 className="text-lg font-semibold mb-4">
            E-commerce Plugin Integration
          </h2>
          <p className="text-sm text-muted-foreground mb-6">
            This demo shows how the product identification system can be integrated
            into an e-commerce platform. Search for products to see their details.
          </p>

          <div className="flex gap-2">
            <Input
              placeholder="Search products..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="max-w-sm"
            />
            <Button>
              <Search className="mr-2 h-4 w-4" />
              Search
            </Button>
          </div>
        </div>

        {products && (
          <div className="grid gap-6 md:grid-cols-2">
            {products.map((product) => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        )}

        {products?.length === 0 && (
          <p className="text-center text-muted-foreground">
            No products found. Try a different search term.
          </p>
        )}
      </div>
    </div>
  );
}
