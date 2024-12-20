// src/hooks/usePopupState.js
import { useState } from 'react';

export const usePopupState = (initialState = {}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [state, setState] = useState(initialState);
  const initialCopy = { ...initialState };

  const open = () => setIsOpen(true);
  const close = () => setIsOpen(false);
  const reset = () => setState({ ...initialCopy }); // Reset state to initial values

  return {
    isOpen,
    state,
    setState,
    open,
    close,
    reset,
  };
};
