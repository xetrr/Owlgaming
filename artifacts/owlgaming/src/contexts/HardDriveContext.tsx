import React, { createContext, useContext, useState, ReactNode } from "react";

interface HardDriveContextType {
  selectedDriveGB: number | null;
  isUnlimited: boolean;
  selectDrive: (gb: number) => void;
  clearDrive: () => void;
  setUnlimited: () => void;
  showPicker: boolean;
  openPicker: (preselectedGB?: number) => void;
  closePicker: () => void;
  preselectedGB: number | undefined;
}

const HardDriveContext = createContext<HardDriveContextType | undefined>(undefined);

export const HardDriveProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [selectedDriveGB, setSelectedDriveGB] = useState<number | null>(null);
  const [isUnlimited, setIsUnlimited] = useState(false);
  const [showPicker, setShowPicker] = useState(false);
  const [preselectedGB, setPreselectedGB] = useState<number | undefined>(undefined);

  const selectDrive = (gb: number) => {
    setSelectedDriveGB(gb);
    setIsUnlimited(false);
    setShowPicker(false);
  };

  const clearDrive = () => {
    setSelectedDriveGB(null);
    setIsUnlimited(false);
  };

  const setUnlimited = () => {
    setIsUnlimited(true);
    setSelectedDriveGB(null);
    setShowPicker(false);
  };

  const openPicker = (gb?: number) => {
    setPreselectedGB(gb);
    setShowPicker(true);
  };

  const closePicker = () => {
    setShowPicker(false);
    setPreselectedGB(undefined);
  };

  return (
    <HardDriveContext.Provider
      value={{
        selectedDriveGB,
        isUnlimited,
        selectDrive,
        clearDrive,
        setUnlimited,
        showPicker,
        openPicker,
        closePicker,
        preselectedGB,
      }}
    >
      {children}
    </HardDriveContext.Provider>
  );
};

export const useHardDrive = (): HardDriveContextType => {
  const ctx = useContext(HardDriveContext);
  if (!ctx) throw new Error("useHardDrive must be used within HardDriveProvider");
  return ctx;
};
