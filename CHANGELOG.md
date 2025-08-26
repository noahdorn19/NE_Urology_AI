## Version 0.19.1 — 2025-08-26  

⚠️ Status: Testing Only  
This version is **still not ready for everyday use**. We’re getting closer, but version 1.0.0 will be the first fully stable release.  

### ✨ What’s New
- You can now **resize the chat list on the left** by dragging it.  
- The **top bar and message box stay fixed** in place when scrolling, so only the chat list and chat messages move.  
- When doctors are listed by initials (like *CTB*), the AI now **adds their full name in parentheses** so you know who it means.  

### 👍 Improvements
- The AI now **sticks to the facts in the database first**. It only “guesses” or digs deeper if it can’t find a clear match.  
- The abbreviation **ED** is always treated as *erectile dysfunction* (not Emergency Department).  
- The AI **asks fewer unnecessary clarifying questions**—only when it really matters.  
- Answers are written **directly to you in plain language**, not copied word-for-word from the files.  
- The chat **bubble style is back** with better spacing, while keeping your light and dark themes.  
- The page no longer scrolls all at once—**the chat list and messages scroll separately**.  
- Searching for answers now happens in a smarter order:  
  1. Look for synonyms (like “unable to urinate” → “urinary retention”),  
  2. Check database rules,  
  3. Look for provider information,  
  4. Suggest related rules if needed,  
  5. Finally, search through files.  

### 🐞 Fixes
- Fixed an issue where the AI could crash if it looked for a helper function too early.  
- Fixed a database error that sometimes broke related rule lookups.  
- Fixed search errors caused by mismatched settings.  
- Cleaned up mistakes in the program code that caused crashes.  
- Stopped the AI from bringing up unrelated scheduling details when answering ED questions.  

---

🔖 **Summary:**  
This version makes the AI **more accurate, easier to read, and less confusing**. It won’t jump to unrelated topics, it explains abbreviations better, and the chat interface looks and works more smoothly. Still in **testing**, but we’re getting closer to a real release.  
