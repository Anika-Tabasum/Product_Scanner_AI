import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import Papa from 'papaparse';

export default function GGSVisualization() {
  const [isLoading, setIsLoading] = useState(true);
  const [data, setData] = useState<{
    gender: { name: string; value: number }[];
    education: { name: string; male: number; female: number }[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadData = async () => {
      try {
        setIsLoading(true);
        console.log('Starting CSV data fetch...');

        const response = await fetch('/GGS_new.csv');
        console.log('Fetch response status:', response.status);

        if (!response.ok) {
          throw new Error(`Failed to fetch CSV: ${response.statusText}`);
        }

        const csvText = await response.text();
        console.log('CSV text length:', csvText.length);
        console.log('First 100 characters:', csvText.substring(0, 100));

        Papa.parse(csvText, {
          header: true,
          skipEmptyLines: true,
          complete: (results) => {
            console.log('Parse complete. Total rows:', results.data.length);
            console.log('Sample row:', results.data[0]);

            // Count gender distribution
            const genderCounts = { male: 0, female: 0 };
            const educationCounts = {
              'High School': { male: 0, female: 0 },
              'Bachelor': { male: 0, female: 0 },
              'Graduate': { male: 0, female: 0 }
            };

            results.data.forEach((row: any) => {
              const sex = parseInt(row.sex);
              const eduLevel = parseInt(row.edu_level);

              // Count gender
              if (sex === 1) genderCounts.male++;
              else if (sex === 2) genderCounts.female++;

              // Count education levels by gender
              if (eduLevel && (sex === 1 || sex === 2)) {
                const gender = sex === 1 ? 'male' : 'female';
                if (eduLevel === 1) educationCounts['High School'][gender]++;
                else if (eduLevel === 2) educationCounts['Bachelor'][gender]++;
                else if (eduLevel === 3) educationCounts['Graduate'][gender]++;
              }
            });

            const processedData = {
              gender: [
                { name: 'Male', value: genderCounts.male },
                { name: 'Female', value: genderCounts.female }
              ],
              education: Object.entries(educationCounts).map(([name, counts]) => ({
                name,
                male: counts.male,
                female: counts.female
              }))
            };

            console.log('Processed data:', processedData);
            setData(processedData);
            setIsLoading(false);
          },
          error: (error) => {
            console.error('CSV parsing error:', error);
            setError('Failed to parse CSV data');
            setIsLoading(false);
          }
        });
      } catch (error) {
        console.error('Error loading data:', error);
        setError(error instanceof Error ? error.message : 'Failed to load data');
        setIsLoading(false);
      }
    };

    loadData();
  }, []);

  if (isLoading) {
    return (
      <div className="container mx-auto p-4 text-center">
        <Loader2 className="h-8 w-8 animate-spin mx-auto" />
        <p className="mt-2">Loading GGS data...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="container mx-auto p-4">
        <div className="text-center text-red-500">
          {error || 'No data available'}
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-8">GGS Data Analysis</h1>

      {/* Gender Distribution */}
      <Card className="mb-8">
        <CardHeader>
          <CardTitle>Gender Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4">
            {data.gender.map((item) => (
              <div 
                key={item.name}
                className={`p-4 rounded-lg ${
                  item.name === 'Male' ? 'bg-blue-100' : 'bg-pink-100'
                }`}
              >
                <h3 className={`text-lg font-semibold ${
                  item.name === 'Male' ? 'text-blue-700' : 'text-pink-700'
                }`}>
                  {item.name}
                </h3>
                <p className={`text-2xl font-bold ${
                  item.name === 'Male' ? 'text-blue-900' : 'text-pink-900'
                }`}>
                  {item.value}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Education Distribution */}
      <Card>
        <CardHeader>
          <CardTitle>Education Level Distribution by Gender</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[400px] w-full">
            <BarChart
              width={800}
              height={400}
              data={data.education}
              margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="male" name="Male" fill="#3b82f6" />
              <Bar dataKey="female" name="Female" fill="#ec4899" />
            </BarChart>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}