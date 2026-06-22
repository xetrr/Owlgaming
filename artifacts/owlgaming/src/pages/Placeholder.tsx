import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";

interface PlaceholderProps {
  title: string;
  description?: string;
}

export default function Placeholder({ title, description }: PlaceholderProps) {
  return (
    <div className="min-h-screen flex items-center justify-center">
      {/* Header spacing */}
      <div className="absolute top-16 left-0 right-0 h-0" />

      <div className="container mx-auto px-4 text-center space-y-6 py-20">
        <div className="space-y-3">
          <h1 className="text-4xl md:text-5xl font-bold text-foreground">
            {title}
          </h1>
          {description && (
            <p className="text-lg text-foreground/70 max-w-2xl mx-auto">
              {description}
            </p>
          )}
        </div>

        <div className="bg-card border border-border rounded-xl p-8 max-w-md mx-auto space-y-4">
          <p className="text-foreground/60">
            This page is coming soon! Continue asking to build out this page content.
          </p>
          <Link
            to="/"
            className="inline-flex items-center justify-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-lg transition-all hover:shadow-lg hover:shadow-primary/20 w-full"
          >
            Back to Home
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    </div>
  );
}
