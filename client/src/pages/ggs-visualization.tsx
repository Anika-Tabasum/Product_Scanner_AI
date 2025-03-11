import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, LineChart, Line, ResponsiveContainer } from 'recharts';

// Constants for data mapping
const GENERATION_LABELS = {
  1: "1930-39",
  2: "1940-49",
  3: "1950-59",
  4: "1960-69",
  5: "1970-79",
  6: "1980-86"
};

const EDUCATION_LABELS = {
  1: "High",
  2: "Middle",
  3: "Low"
};

interface GGSEvent {
  id: number;
  originalId: number;
  sex: number;
  generations: number;
  eduLevel: number;
  age: number;
  eventData: Record<string, string>;
}

interface GGSData {
  genderStats: {
    male: number;
    female: number;
  };
  eventsByGender: {
    male: GGSEvent[];
    female: GGSEvent[];
  };
}

function processGenerationData(events: GGSEvent[]) {
  const generationCounts = Array(6).fill(0);
  events.forEach(event => {
    if (event.generations >= 1 && event.generations <= 6) {
      generationCounts[event.generations - 1]++;
    }
  });
  return Object.entries(GENERATION_LABELS).map(([key, label]) => ({
    name: label,
    count: generationCounts[Number(key) - 1]
  }));
}

function processEducationData(events: GGSEvent[]) {
  const educationCounts = Array(3).fill(0);
  events.forEach(event => {
    if (event.eduLevel >= 1 && event.eduLevel <= 3) {
      educationCounts[event.eduLevel - 1]++;
    }
  });
  return Object.entries(EDUCATION_LABELS).map(([key, label]) => ({
    name: label,
    count: educationCounts[Number(key) - 1]
  }));
}

export default function GGSVisualization() {
  const { data, isLoading, refetch } = useQuery<GGSData>({
    queryKey: ['/api/statuses']
  });

  const importData = async () => {
    try {
      await fetch('/api/ggs/import', { method: 'POST' });
      refetch();
    } catch (error) {
      console.error('Failed to import data:', error);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  const { genderStats = { male: 0, female: 0 }, eventsByGender = { male: [], female: [] } } = data || {};

  const maleGenerationData = processGenerationData(eventsByGender.male);
  const femaleGenerationData = processGenerationData(eventsByGender.female);
  const maleEducationData = processEducationData(eventsByGender.male);
  const femaleEducationData = processEducationData(eventsByGender.female);

  return (
    <div className="container py-8">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold">GGS Data Analysis</h1>
        <Button onClick={importData}>Import GGS Data</Button>
      </div>

      <div className="grid gap-6">
        {/* Gender Distribution Card */}
        <Card>
          <CardHeader>
            <CardTitle>Gender Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-center">
              <div className="p-4 rounded-lg bg-blue-100">
                <h3 className="text-lg font-semibold text-blue-700">Men</h3>
                <p className="text-2xl font-bold text-blue-900">{genderStats.male}</p>
              </div>
              <div className="p-4 rounded-lg bg-pink-100">
                <h3 className="text-lg font-semibold text-pink-700">Women</h3>
                <p className="text-2xl font-bold text-pink-900">{genderStats.female}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Generation Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Generation Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[400px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line
                    data={maleGenerationData}
                    type="monotone"
                    dataKey="count"
                    name="Men"
                    stroke="#3b82f6"
                    strokeWidth={2}
                  />
                  <Line
                    data={femaleGenerationData}
                    type="monotone"
                    dataKey="count"
                    name="Women"
                    stroke="#ec4899"
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Education Level Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Education Level Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[400px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart width={500} height={300} data={maleEducationData.concat(femaleEducationData)}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="count" name="Men" fill="#3b82f6" stackId="a" />
                  <Bar dataKey="count" name="Women" fill="#ec4899" stackId="a" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}