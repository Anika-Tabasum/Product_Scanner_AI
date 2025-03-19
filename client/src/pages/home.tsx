import { useState } from 'react';
import { Link } from 'wouter';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { ImageUpload } from '@/components/image-upload';
import { CameraCapture } from '@/components/camera-capture';
import { ProductCard } from '@/components/product-card';
import { apiRequest } from '@/lib/queryClient';
import { useMutation, useQuery } from '@tanstack/react-query';
import { type Product } from '@shared/schema';
import { Puzzle, LogIn } from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';

// Extended Product type to include temporary products for guests
type ExtendedProduct = Product & {
  temporary?: boolean;
  message?: string;
};

export default function Home() {
  const { toast } = useToast();
  const { isGuest } = useAuth();
  const [processing, setProcessing] = useState(false);
  const [temporaryProduct, setTemporaryProduct] = useState<ExtendedProduct | null>(null);

  const { data: products } = useQuery<Product[]>({
    queryKey: ['/api/products']
  });

  const identifyMutation = useMutation({
    mutationFn: async (image: string) => {
      setProcessing(true);
      const res = await apiRequest('POST', '/api/products/identify', { image });
      return res.json();
    },
    onSuccess: (data) => {
      // Check if it's a temporary product (for guest users)
      if (data.temporary) {
        // Store the temporary product for display
        setTemporaryProduct(data);
        toast({
          title: 'Product Identified',
          description: data.message || 'Product identified but not saved. Create an account to save your products.',
        });
      } else {
        toast({
          title: 'Success',
          description: 'Product successfully identified and added to database',
        });
      }
      setProcessing(false);
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      });
      setProcessing(false);
    }
  });

  const handleImage = (image: string) => {
    identifyMutation.mutate(image);
  };

  return (
    <div className="container mx-auto py-8 px-4">
      <div className="max-w-2xl mx-auto mb-12">
        <h1 className="text-4xl font-bold text-center mb-4 bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
          AI Product Identifier
        </h1>
        <p className="text-center text-muted-foreground mb-8">
          Upload or capture product images to automatically identify and catalog them
        </p>
        
        <div className="grid gap-6">
          <ImageUpload onUpload={handleImage} />
          <div className="text-center text-sm text-muted-foreground">or</div>
          <CameraCapture onCapture={handleImage} />
        </div>

        {processing && (
          <div className="mt-8">
            <Progress value={45} className="mb-2" />
            <p className="text-sm text-center text-muted-foreground">
              Processing image and identifying product...
            </p>
          </div>
        )}

        <div className="mt-8 flex justify-center">
          <Button asChild variant="outline">
            <Link href="/plugin-demo">
              <Puzzle className="mr-2 h-4 w-4" />
              Try Plugin Demo
            </Link>
          </Button>
        </div>
      </div>

      {/* For authenticated users with saved products */}
      {!isGuest && products && products.length > 0 && (
        <div className="mt-16">
          <h2 className="text-2xl font-semibold mb-6">Identified Products</h2>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {products.map((product) => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        </div>
      )}

      {/* For guest users with a temporary product */}
      {isGuest && temporaryProduct && (
        <div className="mt-16">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-semibold">Product Identified</h2>
            <Button asChild variant="default">
              <Link href="/auth">
                <LogIn className="mr-2 h-4 w-4" />
                Create Account to Save
              </Link>
            </Button>
          </div>
          
          <div className="border border-yellow-200 bg-yellow-50 dark:bg-yellow-950/20 dark:border-yellow-900 p-4 rounded-lg mb-6">
            <p className="text-sm text-yellow-800 dark:text-yellow-300">
              As a guest user, this product identification is temporary and won't be saved. 
              Create an account to save your identified products.
            </p>
          </div>
          
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            <ProductCard key="temp" product={temporaryProduct as Product} />
          </div>
        </div>
      )}
    </div>
  );
}
