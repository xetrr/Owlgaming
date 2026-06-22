import { Suspense, lazy } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import Header from "@/components/Header";
import Footer from "@/components/Footer";
import BottomNav from "@/components/BottomNav";
import AuthModal from "@/components/AuthModal";
import CartBar from "@/components/CartBar";
import BrandHead from "@/components/BrandHead";
import ScrollToTop from "@/components/ScrollToTop";
import { CartProvider } from "@/contexts/CartContext";
import { AuthProvider } from "@/contexts/AuthContext";
import { HardDriveProvider } from "@/contexts/HardDriveContext";
import { LanguageProvider } from "@/contexts/LanguageContext";
import HardDrivePickerModal from "@/components/HardDrivePickerModal";

import Index from "./pages/Index";
const Games = lazy(() => import("./pages/Games"));
const Accessories = lazy(() => import("./pages/Accessories"));
const HardDrives = lazy(() => import("./pages/HardDrives"));
const Contact = lazy(() => import("./pages/Contact"));
const Profile = lazy(() => import("./pages/Profile"));
const GameDetail = lazy(() => import("./pages/GameDetail"));
const Cart = lazy(() => import("./pages/Cart"));
const Admin = lazy(() => import("./pages/Admin"));
const Favorites = lazy(() => import("./pages/Favorites"));
const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      gcTime: 5 * 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const PageFallback = () => (
  <div className="min-h-[60vh] flex items-center justify-center">
    <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
  </div>
);

const Layout = ({ children }: { children: React.ReactNode }) => (
  <div className="min-h-screen flex flex-col bg-background">
    <Header />
    <main className="flex-1">{children}</main>
    <Footer />
    <BottomNav />
    <AuthModal />
    <CartBar />
  </div>
);

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <LanguageProvider>
        <AuthProvider>
          <CartProvider>
            <HardDriveProvider>
              <TooltipProvider>
                <BrandHead />
                <Toaster />
                <Sonner />
                <BrowserRouter
                  future={{
                    v7_startTransition: true,
                    v7_relativeSplatPath: true,
                  }}
                >
                  <ScrollToTop />
                  <HardDrivePickerModal />
                  <Suspense fallback={<PageFallback />}>
                    <Routes>
                      <Route path="/" element={<Layout><Index /></Layout>} />
                      <Route path="/games" element={<Layout><Games /></Layout>} />
                      <Route path="/game/:id" element={<Layout><GameDetail /></Layout>} />
                      <Route path="/accessories" element={<Layout><Accessories /></Layout>} />
                      <Route path="/harddisks" element={<Layout><HardDrives /></Layout>} />
                      <Route path="/contact" element={<Layout><Contact /></Layout>} />
                      <Route path="/profile" element={<Layout><Profile /></Layout>} />
                      <Route path="/favorites" element={<Layout><Favorites /></Layout>} />
                      <Route path="/cart" element={<Layout><Cart /></Layout>} />
                      <Route path="/admin" element={<Admin />} />
                      <Route path="*" element={<Layout><NotFound /></Layout>} />
                    </Routes>
                  </Suspense>
                </BrowserRouter>
              </TooltipProvider>
            </HardDriveProvider>
          </CartProvider>
        </AuthProvider>
      </LanguageProvider>
    </QueryClientProvider>
  );
}

export default App;
