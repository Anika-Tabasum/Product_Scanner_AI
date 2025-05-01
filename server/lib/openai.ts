import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
export async function identifyProduct(image: string, extractedText: string): Promise<{
  name: string;
  description: string;
  brand: string;
  category: string;
}> {
  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        {
          role: "system",
          content: "You are a product identification expert. Analyze the image and extracted text to identify product details. Provide detailed and accurate product information."
        },
        {
          role: "user",
          content: [
            {
              type: "text",
              text: `Please analyze this product. The OCR extracted text is: ${extractedText}. Identify the product name, provide a detailed description, identify the brand, and categorize the product. Respond in JSON format with the following fields: name, description, brand, category.`
            },
            {
              type: "image_url",
              image_url: {
                url: image.startsWith('data:') ? image : `data:image/jpeg;base64,${image}`
              }
            }
          ]
        }
      ],
      response_format: { type: "json_object" },
      max_tokens: 500
    });

    const content = response.choices[0].message.content;
    if (!content) {
      throw new Error("No response received from OpenAI");
    }

    return JSON.parse(content);
  } catch (error) {
    console.error('OpenAI Error:', error);
    throw new Error('Failed to identify product');
  }
}