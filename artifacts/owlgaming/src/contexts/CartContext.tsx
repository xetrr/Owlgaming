import React, { createContext, useContext, useReducer, useMemo, useCallback, useEffect, ReactNode } from "react";
import { roundUpGameSizeGB } from "@/lib/sizeUtils";

const CART_STORAGE_KEY = "gamearly:cart";

const loadInitialCart = (): CartState => {
  if (typeof window === "undefined") return { items: [] };
  try {
    const raw = localStorage.getItem(CART_STORAGE_KEY);
    if (!raw) return { items: [] };
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.items)) return parsed;
    return { items: [] };
  } catch {
    return { items: [] };
  }
};

export interface CartItem {
  id: string;
  title: string;
  size: string;
  price: number;
  quantity: number;
  image: string;
}

interface CartState {
  items: CartItem[];
}

type CartAction =
  | { type: "ADD_ITEM"; payload: Omit<CartItem, "quantity"> }
  | { type: "REMOVE_ITEM"; payload: string }
  | { type: "UPDATE_QUANTITY"; payload: { id: string; quantity: number } }
  | { type: "CLEAR_CART" };

interface CartContextType {
  state: CartState;
  addItem: (item: Omit<CartItem, "quantity">) => void;
  removeItem: (id: string) => void;
  updateQuantity: (id: string, quantity: number) => void;
  clearCart: () => void;
  getTotalSize: () => string;
  getTotalSizeGB: () => number;
  getTotalPrice: () => number;
  getTotalItems: () => number;
  usedGB: number;
  itemIds: Set<string>;
}

const CartContext = createContext<CartContextType | undefined>(undefined);

const cartReducer = (state: CartState, action: CartAction): CartState => {
  switch (action.type) {
    case "ADD_ITEM": {
      const existingItem = state.items.find((item) => item.id === action.payload.id);
      if (existingItem) {
        return {
          items: state.items.map((item) =>
            item.id === action.payload.id
              ? { ...item, quantity: item.quantity + 1 }
              : item
          ),
        };
      }
      return {
        items: [...state.items, { ...action.payload, quantity: 1 }],
      };
    }

    case "REMOVE_ITEM":
      return {
        items: state.items.filter((item) => item.id !== action.payload),
      };

    case "UPDATE_QUANTITY":
      return {
        items: state.items.map((item) =>
          item.id === action.payload.id
            ? { ...item, quantity: action.payload.quantity }
            : item
        ),
      };

    case "CLEAR_CART":
      return { items: [] };

    default:
      return state;
  }
};

export const CartProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [state, dispatch] = useReducer(cartReducer, undefined as unknown as CartState, loadInitialCart);

  useEffect(() => {
    try {
      localStorage.setItem(CART_STORAGE_KEY, JSON.stringify(state));
    } catch {
      /* storage full or unavailable — ignore */
    }
  }, [state]);

  const addItem = useCallback((item: Omit<CartItem, "quantity">) => {
    dispatch({ type: "ADD_ITEM", payload: item });
  }, []);

  const removeItem = useCallback((id: string) => {
    dispatch({ type: "REMOVE_ITEM", payload: id });
  }, []);

  const updateQuantity = useCallback((id: string, quantity: number) => {
    if (quantity <= 0) {
      dispatch({ type: "REMOVE_ITEM", payload: id });
    } else {
      dispatch({ type: "UPDATE_QUANTITY", payload: { id, quantity } });
    }
  }, []);

  const clearCart = useCallback(() => {
    dispatch({ type: "CLEAR_CART" });
  }, []);

  const usedGB = useMemo(
    () => state.items.reduce((acc, item) => acc + roundUpGameSizeGB(item.size) * item.quantity, 0),
    [state.items]
  );

  const itemIds = useMemo(() => new Set(state.items.map((i) => i.id)), [state.items]);

  const getTotalSizeGB = useCallback((): number => {
    let totalGB = 0;
    state.items.forEach((item) => {
      const gbValue = parseFloat(item.size.replace(/[^0-9.]/g, ""));
      if (!isNaN(gbValue)) totalGB += gbValue * item.quantity;
    });
    return totalGB;
  }, [state.items]);

  const getTotalSize = useCallback((): string => `${getTotalSizeGB().toFixed(2)}GB`, [getTotalSizeGB]);

  const getTotalPrice = useCallback(
    (): number => state.items.reduce((total, item) => total + item.price * item.quantity, 0),
    [state.items]
  );

  const getTotalItems = useCallback(
    (): number => state.items.reduce((total, item) => total + item.quantity, 0),
    [state.items]
  );

  const value = useMemo(
    () => ({
      state,
      addItem,
      removeItem,
      updateQuantity,
      clearCart,
      getTotalSize,
      getTotalSizeGB,
      getTotalPrice,
      getTotalItems,
      usedGB,
      itemIds,
    }),
    [state, addItem, removeItem, updateQuantity, clearCart, getTotalSize, getTotalSizeGB, getTotalPrice, getTotalItems, usedGB, itemIds]
  );

  return <CartContext.Provider value={value}>{children}</CartContext.Provider>;
};

export const useCart = (): CartContextType => {
  const context = useContext(CartContext);
  if (!context) {
    throw new Error("useCart must be used within a CartProvider");
  }
  return context;
};
