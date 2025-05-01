import { Button } from '@/components/ui/button';
import { Upload } from 'lucide-react';
import { useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { compressImage } from '@/lib/utils';

interface ImageUploadProps {
  onUpload: (base64: string) => void;
}

export function ImageUpload({ onUpload }: ImageUploadProps) {
  const onDrop = useCallback(
    async (acceptedFiles: File[]) => {
      const file = acceptedFiles[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = async () => {
          try {
            const base64 = (reader.result as string).split(',')[1];
            const compressed = await compressImage(base64);
            onUpload(compressed);
          } catch (error) {
            console.error('Failed to compress image:', error);
          }
        };
        reader.readAsDataURL(file);
      }
    },
    [onUpload]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'image/*': [] },
    maxFiles: 1,
    maxSize: 10 * 1024 * 1024, // 10MB max
  });

  return (
    <div
      {...getRootProps()}
      className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors
        ${isDragActive ? 'border-primary bg-primary/5' : 'border-border'}`}
    >
      <input {...getInputProps()} />
      <Upload className="mx-auto h-8 w-8 mb-2 text-muted-foreground" />
      <p className="text-sm text-muted-foreground">
        {isDragActive
          ? 'Drop the image here'
          : 'Drag & drop an image here, or click to select'}
      </p>
      <Button variant="secondary" className="mt-4">
        Select Image
      </Button>
    </div>
  );
}