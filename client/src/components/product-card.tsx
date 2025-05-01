import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { type Product } from '@shared/schema';

// Extended Product type to include temporary products for guests
type ExtendedProduct = Product & {
  temporary?: boolean;
  message?: string;
};

interface ProductCardProps {
  product: Product | ExtendedProduct;
}

export function ProductCard({ product }: ProductCardProps) {
  // Check if it's a temporary product (for guests)
  const isTemporary = 'temporary' in product && product.temporary === true;

  return (
    <Card className={`overflow-hidden ${isTemporary ? 'border-dashed border-2 border-yellow-400 dark:border-yellow-700' : ''}`}>
      {product.imageUrl && (
        <div className="aspect-video relative overflow-hidden">
          <img
            src={`data:image/jpeg;base64,${product.imageUrl}`}
            alt={product.name}
            className="object-cover w-full h-full"
          />
        </div>
      )}
      <CardHeader>
        <div className="flex items-start justify-between">
          <CardTitle className="text-lg">{product.name}</CardTitle>
          {product.brand && (
            <Badge variant="secondary">{product.brand}</Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground mb-2">
          {product.description}
        </p>
        <div className="flex flex-wrap gap-2">
          {product.category && (
            <Badge variant="outline">{product.category}</Badge>
          )}
          {isTemporary && (
            <Badge variant="outline" className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 hover:bg-yellow-100 dark:hover:bg-yellow-900">
              Temporary
            </Badge>
          )}
        </div>
      </CardContent>
      
      {isTemporary && (
        <CardFooter className="bg-yellow-50 dark:bg-yellow-950/20 border-t border-yellow-200 dark:border-yellow-900 text-xs text-yellow-800 dark:text-yellow-300">
          This product is temporary and won't be saved to your account.
        </CardFooter>
      )}
    </Card>
  );
}
