import Tesseract from "tesseract.js";

export async function extractTextFromImage(imageData: string): Promise<string> {
  try {
    // Ensure image data is properly formatted
    const imageUrl = imageData.startsWith('data:') 
      ? imageData 
      : `data:image/jpeg;base64,${imageData}`;

    console.log('Starting OCR with Tesseract...');
    const result = await Tesseract.recognize(
      imageUrl,
      'eng',
      { 
        logger: m => console.log('Tesseract progress:', m),
        errorHandler: err => console.error('Tesseract error:', err)
      }
    );

    if (!result?.data?.text) {
      throw new Error('No text was extracted from the image');
    }

    console.log('OCR completed successfully');
    return result.data.text.trim();
  } catch (error) {
    console.error('OCR Error:', error);
    throw new Error(`Failed to extract text from image: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}