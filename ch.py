# chatbot_logic.py

from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import os
from dotenv import load_dotenv
load_dotenv()
# ⚠️ Replace with your actual GROQ API key or load from environment variable
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Initialize the Groq LLM
llm = ChatGroq(
    model="llama-3.3-70b-versatile",  # Replace with a model your key has access to
    temperature=0.3,
    api_key=GROQ_API_KEY
)

# Set up the prompt template
prompt_template = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful AI assistant."),
    ("human", "{question}")
])

# Create the chain
chain = prompt_template | llm | StrOutputParser()

# In-memory chat history
chat_history = []  # Each entry: {"role": "user"/"assistant", "content": "message"}


def get_ai_response(user_message: str) -> str:
    """
    Sends the user's message to the AI and remembers the conversation.
    
    Args:
        user_message (str): The message sent by the user.
    
    Returns:
        str: AI assistant response.
    """
    global chat_history

    # Add user message to chat history
    chat_history.append({"role": "user", "content": user_message})

    # Prepare the conversation for the AI prompt
    conversation_context = ""
    for msg in chat_history:
        role = "User" if msg["role"] == "user" else "AI"
        conversation_context += f"{role}: {msg['content']}\n"

    try:
        # Ask the AI using the entire conversation as context
        response = chain.invoke({"question": conversation_context})
    except Exception as e:
        print(f"Error in get_ai_response: {e}")
        response = f"[Mock AI] You said: {user_message}"

    # Add AI response to chat history
    chat_history.append({"role": "assistant", "content": response})

    return response


# Standalone test
if __name__ == "__main__":
    print("Chatbot is running. Type your message (type 'exit' to quit):")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            break
        ai_response = get_ai_response(user_input)
        print(f"AI: {ai_response}")
