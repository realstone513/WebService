// src/types/FeatureTypes.ts

export interface DetectionResult {
  objects: { name: string; confidence: number }[];
}

export interface Message {
  sender: string;
  text: string;
  imageUrl?: string;
}

export interface ChatMessagesProps {
  messages: Message[];
}

export interface ChatInputProps {
  addMessage: (message: { text: string; sender: string }) => void;
  toggleOptions: () => void;
  disabled: boolean;
}
