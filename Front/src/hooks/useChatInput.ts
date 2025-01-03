// src/hooks/useChatInput.ts

import { useState } from 'react';
import botAvatar from '../assets/bot-avatar.png';
import { Message, Sender } from '../types/FeatureTypes';

export const useChatInput = (addMessage: (message: Message) => void) => {
  const [input, setInput] = useState<string>('');

  const handleInputChange = (value: string) => {
    setInput(value);
  };

  const handleSendMessage = () => {
    if (input.trim() !== '') {
      const messageToAdd: Message = input.startsWith('#')
        ? { text: input.slice(1).trim(), sender: Sender.Bot, imageUrl: botAvatar }
        : { text: input, sender: Sender.User };

      addMessage(messageToAdd);
      setInput('');
    }
  };

  return {
    input,
    handleInputChange,
    handleSendMessage,
  };
};
