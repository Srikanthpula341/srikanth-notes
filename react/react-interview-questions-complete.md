# React Interview Questions & Answers
## Complete Guide: Basic to Advanced

---

## Table of Contents

### Part 1: Fundamentals (Q1-Q10)
1. What is React and why use it?
2. JSX explained
3. Components vs Elements  
4. Props in React
5. State in React
6. Virtual DOM
7. Controlled vs Uncontrolled Components
8. React Fragments

### Part 2: Intermediate (Q9-Q15)
9. Component Lifecycle
10. useState vs useReducer
11. Prop Drilling Solutions
12. Context API
13. Higher-Order Components
14. React Fiber
15. React Portals
16. Error Boundaries

### Part 3: Hooks (Q17-Q19)
17. Rules of Hooks
18. useEffect vs useLayoutEffect
19. useCallback vs useMemo

### Part 4: Advanced Topics (Q20-Q30)
20. Render Props Pattern
21. Code Splitting Strategies
22. React Performance Optimization
23. Custom Hooks Best Practices
24. Server-Side Rendering
25. React 18 Concurrent Features

### Part 5: Coding Questions (Q31-Q40)

---

## PART 1: FUNDAMENTALS

### Q1: What is React? Why use React instead of vanilla JavaScript?

**Answer:**
React is a JavaScript library for building user interfaces, created by Facebook. It focuses on creating reusable UI components.

**Why React over vanilla JS:**

1. **Component-Based**: Break UI into reusable pieces instead of monolithic code
2. **Declarative**: Describe what UI should look like, React handles how
3. **Virtual DOM**: Efficient updates - only changes what's necessary
4. **State Management**: Automatic UI updates when data changes
5. **Ecosystem**: Rich tools and community

**Comparison:**
```
Vanilla JS: Imperative, manual DOM manipulation, harder to organize
React: Declarative, automatic updates, component-based structure
```

---

### Q2: What is JSX?

**Answer:**
JSX (JavaScript XML) is a syntax extension that looks like HTML but is actually JavaScript.

**Key Points:**
- Not HTML - it's syntactic sugar for React.createElement()
- Type-safe - catches errors at compile time
- Allows embedding JavaScript expressions with {}
- Transformed by Babel into React function calls

**Rules:**
1. Must return single parent element (or Fragment)
2. All tags must be closed
3. Use className (not class)
4. camelCase for attributes
5. JavaScript expressions in {}

**Interview Tip:** "JSX is optional but makes code much more readable than nested function calls."

---

### Q3: Components vs Elements

**Answer:**

**Element:**
- Plain JavaScript object describing UI
- Immutable once created
- Cheap to create
- Return value of React.createElement()

**Component:**
- Function or class that returns elements
- Can have state and logic
- Reusable blueprint
- Can contain lifecycle methods

**Analogy:**
- Component = Recipe (instructions)
- Element = Dish (result)

---

### Q4: Props in React

**Answer:**
Props (properties) are arguments passed from parent to child components.

**Characteristics:**
1. **Read-only** - child cannot modify props
2. **Unidirectional** - data flows parent → child
3. **Any type** - strings, numbers, objects, functions, components
4. **Immutable** - ensures predictability

**Why Immutable:**
- Predictable rendering
- Pure functions
- Performance optimizations
- Easier debugging

**Interview Tip:** "Props are like function parameters - you read them but don't modify them inside the function."

---

### Q5: State vs Props

**Answer:**

| Aspect | Props | State |
|--------|-------|-------|
| Ownership | External | Internal |
| Mutability | Immutable | Mutable (via setState) |
| Source | Parent | Component itself |
| Changes | Parent re-renders | Component re-renders |
| Purpose | Configure component | Manage data |

**When to use State:**
- Data that changes over time
- User interactions (forms, toggles)
- Data local to component

**When to use Props:**
- Pass data parent → child
- Configure components
- Callback functions

**Important:** State updates are asynchronous for performance (batching).

---

### Q6: Virtual DOM

**Answer:**
Virtual DOM is a JavaScript representation of the actual DOM, enabling efficient updates.

**How it works:**

**Step 1:** Create virtual representation
- JavaScript object tree mimicking DOM
- Fast to manipulate

**Step 2:** Reconciliation (Diffing)
- Compare new Virtual DOM with previous
- Identify what changed

**Step 3:** Minimal updates
- Update only changed parts in real DOM
- Batch updates for efficiency

**Why it's fast:**
- Batches multiple updates into one
- Updates only what changed
- JavaScript operations (fast) vs DOM operations (slow)

**Interview Tip:** "Virtual DOM is React's mechanism for efficient updates, not the reason React is fast - batching and minimal updates are what make it fast."

---

### Q7: Controlled vs Uncontrolled Components

**Answer:**

**Controlled Component:**
- React state controls form input value
- Every keystroke updates state
- State is "single source of truth"

**Use when:**
- Need validation on every keystroke
- Format input (uppercase, phone masks)
- Conditional logic based on input
- Disable submit until valid

**Uncontrolled Component:**
- DOM maintains input value
- Use refs to access value when needed
- Less code, no state per input

**Use when:**
- Simple forms without validation
- File inputs (must be uncontrolled)
- Performance-critical forms
- Integration with non-React code

**Interview Tip:** "React recommends controlled for most cases - it's more 'React-like' and gives you more control."

---

### Q8: React Fragments

**Answer:**
Fragments let you group children without adding extra DOM nodes.

**The Problem:** Components must return single element, leading to unnecessary divs

**Solution:**
```jsx
// Short syntax
<>
  <Child1 />
  <Child2 />
</>

// Full syntax (when you need keys)
<React.Fragment key={item.id}>
  <dt>{item.term}</dt>
  <dd>{item.description}</dd>
</React.Fragment>
```

**Benefits:**
1. Cleaner DOM - no wrapper divs
2. Better performance - fewer nodes
3. Proper HTML structure (tables, lists)
4. Doesn't break CSS layouts (flexbox/grid)

---

## PART 2: INTERMEDIATE CONCEPTS

### Q9: Component Lifecycle

**Answer:**
Lifecycle is the series of phases from creation to removal.

**Three Phases:**

1. **Mounting** - Component created and inserted
   - constructor → getDerivedStateFromProps → render → componentDidMount

2. **Updating** - Re-render due to prop/state changes
   - getDerivedStateFromProps → shouldComponentUpdate → render → componentDidUpdate

3. **Unmounting** - Component removed
   - componentWillUnmount

**Modern (Hooks):**
```javascript
useEffect(() => {
  // componentDidMount + componentDidUpdate
  
  return () => {
    // componentWillUnmount
  };
});

useEffect(() => {
  // componentDidMount only
}, []);

useEffect(() => {
  // When dependencies change
}, [dep1, dep2]);
```

**Interview Tip:** "Focus on hooks unless specifically asked about class components. Lifecycle methods are legacy."

---

### Q10: useState vs useReducer

**Answer:**

**useState - Simple State:**
- Single values
- Simple updates
- Independent state variables

**useReducer - Complex State:**
- Complex objects with sub-values
- State updates depend on previous state
- Complex update logic
- Multiple related states

**When to switch:**
- Multiple setState calls in one function
- State updates interdependent
- Need to pass update logic to children
- State shape complex

**Interview Tip:** "Start with useState. Switch to useReducer when useState becomes messy with too many related state variables."

---

### Q11: Prop Drilling Solutions

**Answer:**
Prop drilling is passing props through components that don't use them.

**Solutions:**

1. **Context API** (Most common)
   - Create context at top level
   - Consume anywhere in tree
   - No props through intermediate components

2. **Component Composition** (Often best)
   - Pass components as children
   - No need to pass data down

3. **State Management** (Large apps)
   - Redux, Zustand, Recoil
   - Global state accessible anywhere

4. **Custom Hooks**
   - Encapsulate logic
   - Better API

**Interview Tip:** "Try component composition first, then Context. Don't immediately reach for Redux."

---

### Q12: Context API

**Answer:**
Context shares data across component tree without prop drilling.

**How it works:**
1. Create Context: `createContext()`
2. Provide at top: `<Context.Provider value={...}>`
3. Consume anywhere: `useContext(Context)`

**Common Use Cases:**
- Theme/dark mode
- Authentication
- Language/locale
- App-wide settings

**Performance Issue:**
All consumers re-render when context value changes.

**Solutions:**
1. Split contexts (separate concerns)
2. Memoize context value
3. Separate state and dispatch contexts

**Interview Tip:** "Context is great for infrequently changing data. For frequently changing state, consider performance implications or use state management library."

---

### Q13: Higher-Order Components (HOCs)

**Answer:**
HOC is a function that takes a component and returns enhanced component.

**Structure:**
```javascript
function withAuth(Component) {
  return function EnhancedComponent(props) {
    const user = useAuth();
    if (!user) return <Navigate to="/login" />;
    return <Component {...props} user={user} />;
  };
}
```

**Use Cases:**
- Authentication checks
- Loading states
- Error boundaries
- Analytics tracking

**HOCs vs Hooks:**
- Hooks largely replaced HOCs
- HOCs still useful for class components
- Hooks are simpler and more readable

**Interview Tip:** "HOCs were common before hooks. Now mostly use custom hooks for logic reuse, but HOCs still valid for certain patterns like authentication wrappers."

---

### Q14: React Fiber

**Answer:**
Fiber is React's reconciliation engine (introduced React 16) that allows interruptible rendering.

**Old Problem:**
- Synchronous rendering
- Long updates blocked UI
- Janky animations

**Fiber Solution:**
- Pause and resume work
- Assign priority to updates
- Time-slicing (break work into chunks)
- Responsive UI even during large updates

**Key Concepts:**
1. **Work-in-progress tree** - enables interruption
2. **Priority levels** - user input > data fetching
3. **Phases**: Render (interruptible) and Commit (not interruptible)

**Benefits:**
- Better responsiveness
- Smoother animations
- Enabled Suspense and Concurrent Mode

**Interview Tip:** "Fiber works behind the scenes - developers don't change code, but it enables features like Suspense and improves UX by keeping UI responsive."

---

### Q15: React Portals

**Answer:**
Portals render children into DOM node outside parent hierarchy.

**Use Cases:**
- Modals/dialogs
- Tooltips
- Dropdowns
- Notifications

**Why:**
- Escape parent's overflow: hidden
- Higher z-index
- Position: fixed works correctly
- Better accessibility

**Key Behavior:**
- Event bubbling works through React tree (not DOM tree)
- Context still works
- React parent-child relationship preserved

**Interview Tip:** "Portals solve CSS problems (overflow, z-index) while maintaining React's component relationship for events and context."

---

### Q16: Error Boundaries

**Answer:**
Error Boundaries catch JavaScript errors in child components, log them, and show fallback UI.

**Implementation (Class only):**
```javascript
class ErrorBoundary extends React.Component {
  state = { hasError: false };
  
  static getDerivedStateFromError(error) {
    return { hasError: true };
  }
  
  componentDidCatch(error, errorInfo) {
    logErrorToService(error, errorInfo);
  }
  
  render() {
    if (this.state.hasError) {
      return <h1>Something went wrong</h1>;
    }
    return this.props.children;
  }
}
```

**What they catch:**
✅ Render errors
✅ Lifecycle errors
✅ Constructor errors

**What they DON'T catch:**
❌ Event handlers
❌ Async code
❌ Server-side rendering
❌ Errors in Error Boundary itself

**Best Practice:** Use multiple boundaries, not just one at top level.

**Interview Tip:** "Error Boundaries must be class components (for now). They prevent entire app crash and are essential for production."

---

## PART 3: HOOKS DEEP DIVE

### Q17: Rules of Hooks

**Answer:**
Two fundamental rules:

**Rule 1: Only Call at Top Level**
- Never in conditions, loops, or nested functions
- Must be called in same order every render

**Rule 2: Only in React Functions**
- React components or custom hooks only
- Not in regular JavaScript functions

**Why:**
React stores hooks in linked list by call order. Changing order breaks internal tracking.

**ESLint Plugin:**
`eslint-plugin-react-hooks` catches violations automatically.

**Interview Tip:** "These aren't suggestions - they're requirements for React to work correctly. React relies on call order to match hook data."

---

### Q18: useEffect vs useLayoutEffect

**Answer:**

**useEffect (Most Common - 95%):**
- Runs AFTER browser paints
- Non-blocking
- Use for: data fetching, subscriptions, most side effects

**useLayoutEffect (Rare - 4%):**
- Runs BEFORE browser paints
- Blocks painting
- Use for: DOM measurements, preventing visual flicker

**useInsertionEffect (Very Rare - 1%):**
- Runs BEFORE DOM mutations
- CSS-in-JS libraries only

**Timeline:**
```
Render → Insert CSS → Commit DOM → useLayoutEffect → Paint → useEffect
```

**Decision:**
- Need to prevent flicker? → useLayoutEffect
- Everything else? → useEffect

**Interview Tip:** "Default to useEffect. Only use useLayoutEffect when you specifically need to read layout or prevent visual flicker."

---

### Q19: useCallback vs useMemo

**Answer:**

**Fundamental Difference:**
- useMemo: memoizes return VALUE
- useCallback: memoizes FUNCTION itself

**useMemo - Computed Values:**
```javascript
const expensiveValue = useMemo(() => {
  return computeExpensive(a, b);
}, [a, b]);
```

Use for: Expensive calculations, array transformations

**useCallback - Function References:**
```javascript
const memoizedFn = useCallback(() => {
  doSomething(a, b);
}, [a, b]);
```

Use for: Passing to memo'd components, useEffect dependencies

**When NOT to use:**
- Don't overuse (premature optimization)
- Simple calculations don't need memoization
- Only use when you measure performance problem

**Interview Tip:** "useCallback is actually useMemo(() => fn). Use for referential equality, not premature optimization."

---

## PART 4: PATTERNS & BEST PRACTICES

### Q20: Render Props Pattern

**Answer:**
Component takes function as prop that returns what to render.

**Structure:**
```jsx
<DataProvider render={(data) => <Display data={data} />} />
```

**Modern Alternative: Hooks**
Hooks largely replaced render props for cleaner code.

**When still useful:**
- Working with class components
- Third-party libraries
- Specific composition patterns

---

### Q21: Code Splitting Strategies

**Answer:**
Load code on demand to reduce initial bundle size.

**Techniques:**

1. **Route-based** (Most common)
```javascript
const Dashboard = lazy(() => import('./Dashboard'));
```

2. **Component-based** (Heavy components)
```javascript
const Chart = lazy(() => import('./Chart'));
```

3. **Library splitting** (Large dependencies)
```javascript
const HeavyLib = lazy(() => import('./HeavyLib'));
```

**Best Practices:**
- Split by route first
- Split heavy components
- Use Suspense for fallback
- Preload on hover (predictive)

---

### Q22: React Performance Optimization

**Answer:**

**Key Techniques:**

1. **React.memo** - Prevent unnecessary re-renders
2. **useMemo** - Memoize expensive calculations
3. **useCallback** - Stable function references
4. **Code Splitting** - Reduce initial load
5. **Virtual Lists** - For large lists (react-window)
6. **Keys** - Proper keys for lists
7. **Lazy Loading** - Images, components

**Common Mistakes:**
- Over-optimization (premature)
- Wrong keys (using index)
- Not measuring before optimizing

**Interview Tip:** "Always profile first, optimize second. Don't guess - measure with React DevTools Profiler."

---

### Q23: Custom Hooks Best Practices

**Answer:**

**Rules:**
1. Name must start with "use"
2. Follow all hook rules
3. Return consistent data structure
4. Document dependencies
5. Keep focused (single responsibility)

**Good Custom Hook:**
```javascript
function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    checkAuth().then(user => {
      setUser(user);
      setLoading(false);
    });
  }, []);
  
  return { user, loading };
}
```

---

### Q24: Key React Concepts Summary

**Component Design:**
- Keep components small and focused
- Extract reusable logic to hooks
- Use composition over inheritance

**State Management:**
- Keep state close to where it's used
- Lift state up when needed
- Context for global state
- Redux/Zustand for complex apps

**Performance:**
- Profile before optimizing
- Use keys correctly
- Memoize when necessary
- Code split by route

---

## PART 5: CODING QUESTIONS

### Q31: Build a Counter with Increment/Decrement

```javascript
function Counter() {
  const [count, setCount] = useState(0);
  
  return (
    <div>
      <h1>Count: {count}</h1>
      <button onClick={() => setCount(count - 1)}>-</button>
      <button onClick={() => setCount(count + 1)}>+</button>
      <button onClick={() => setCount(0)}>Reset</button>
    </div>
  );
}
```

---

### Q32: Fetch and Display Data

```javascript
function UserList() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    fetch('/api/users')
      .then(res => res.json())
      .then(data => {
        setUsers(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  
  return (
    <ul>
      {users.map(user => (
        <li key={user.id}>{user.name}</li>
      ))}
    </ul>
  );
}
```

---

### Q33: Form with Controlled Inputs

```javascript
function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({});
  
  const validate = () => {
    const newErrors = {};
    if (!email.includes('@')) {
      newErrors.email = 'Invalid email';
    }
    if (password.length < 8) {
      newErrors.password = 'Password must be 8+ characters';
    }
    return newErrors;
  };
  
  const handleSubmit = (e) => {
    e.preventDefault();
    const newErrors = validate();
    
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    
    // Submit form
    console.log('Submitted:', { email, password });
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <div>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
        />
        {errors.email && <span>{errors.email}</span>}
      </div>
      
      <div>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
        />
        {errors.password && <span>{errors.password}</span>}
      </div>
      
      <button type="submit">Login</button>
    </form>
  );
}
```

---

### Q34: Todo List with Add/Delete

```javascript
function TodoList() {
  const [todos, setTodos] = useState([]);
  const [input, setInput] = useState('');
  
  const addTodo = () => {
    if (!input.trim()) return;
    setTodos([...todos, { id: Date.now(), text: input, completed: false }]);
    setInput('');
  };
  
  const toggleTodo = (id) => {
    setTodos(todos.map(todo =>
      todo.id === id ? { ...todo, completed: !todo.completed } : todo
    ));
  };
  
  const deleteTodo = (id) => {
    setTodos(todos.filter(todo => todo.id !== id));
  };
  
  return (
    <div>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyPress={(e) => e.key === 'Enter' && addTodo()}
      />
      <button onClick={addTodo}>Add</button>
      
      <ul>
        {todos.map(todo => (
          <li key={todo.id}>
            <input
              type="checkbox"
              checked={todo.completed}
              onChange={() => toggleTodo(todo.id)}
            />
            <span style={{ textDecoration: todo.completed ? 'line-through' : 'none' }}>
              {todo.text}
            </span>
            <button onClick={() => deleteTodo(todo.id)}>Delete</button>
          </li>
        ))}
      </ul>
    </div>
  );
}
```

---

### Q35: Custom Hook - useDebounce

```javascript
function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = useState(value);
  
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);
    
    return () => clearTimeout(timer);
  }, [value, delay]);
  
  return debouncedValue;
}

// Usage
function SearchBox() {
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebounce(query, 500);
  
  useEffect(() => {
    if (debouncedQuery) {
      // API call only after user stops typing for 500ms
      searchAPI(debouncedQuery);
    }
  }, [debouncedQuery]);
  
  return (
    <input
      value={query}
      onChange={(e) => setQuery(e.target.value)}
      placeholder="Search..."
    />
  );
}
```

---

### Q36: Custom Hook - useLocalStorage

```javascript
function useLocalStorage(key, initialValue) {
  const [value, setValue] = useState(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      return initialValue;
    }
  });
  
  const setStoredValue = (newValue) => {
    try {
      setValue(newValue);
      window.localStorage.setItem(key, JSON.stringify(newValue));
    } catch (error) {
      console.error('Error saving to localStorage:', error);
    }
  };
  
  return [value, setStoredValue];
}

// Usage
function App() {
  const [name, setName] = useLocalStorage('name', '');
  
  return (
    <input
      value={name}
      onChange={(e) => setName(e.target.value)}
    />
  );
}
```

---

### Q37: Modal Component

```javascript
function Modal({ isOpen, onClose, children }) {
  if (!isOpen) return null;
  
  return createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>×</button>
        {children}
      </div>
    </div>,
    document.getElementById('modal-root')
  );
}

// Usage
function App() {
  const [isOpen, setIsOpen] = useState(false);
  
  return (
    <>
      <button onClick={() => setIsOpen(true)}>Open Modal</button>
      <Modal isOpen={isOpen} onClose={() => setIsOpen(false)}>
        <h2>Modal Title</h2>
        <p>Modal content here</p>
      </Modal>
    </>
  );
}
```

---

### Q38: Pagination Component

```javascript
function Pagination({ totalItems, itemsPerPage, currentPage, onPageChange }) {
  const totalPages = Math.ceil(totalItems / itemsPerPage);
  
  const pages = Array.from({ length: totalPages }, (_, i) => i + 1);
  
  return (
    <div className="pagination">
      <button
        onClick={() => onPageChange(currentPage - 1)}
        disabled={currentPage === 1}
      >
        Previous
      </button>
      
      {pages.map(page => (
        <button
          key={page}
          onClick={() => onPageChange(page)}
          className={page === currentPage ? 'active' : ''}
        >
          {page}
        </button>
      ))}
      
      <button
        onClick={() => onPageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
      >
        Next
      </button>
    </div>
  );
}
```

---

### Q39: Infinite Scroll

```javascript
function InfiniteScroll() {
  const [items, setItems] = useState([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const observerRef = useRef();
  
  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;
    
    setLoading(true);
    const newItems = await fetchItems(page);
    
    if (newItems.length === 0) {
      setHasMore(false);
    } else {
      setItems(prev => [...prev, ...newItems]);
      setPage(prev => prev + 1);
    }
    
    setLoading(false);
  }, [page, loading, hasMore]);
  
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          loadMore();
        }
      },
      { threshold: 1 }
    );
    
    if (observerRef.current) {
      observer.observe(observerRef.current);
    }
    
    return () => observer.disconnect();
  }, [loadMore]);
  
  return (
    <div>
      {items.map(item => (
        <div key={item.id}>{item.content}</div>
      ))}
      {loading && <div>Loading...</div>}
      {hasMore && <div ref={observerRef} style={{ height: '20px' }} />}
    </div>
  );
}
```

---

### Q40: Search with Filters

```javascript
function SearchableList({ items }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  
  const filteredItems = useMemo(() => {
    return items
      .filter(item => {
        // Search filter
        if (query && !item.name.toLowerCase().includes(query.toLowerCase())) {
          return false;
        }
        
        // Category filter
        if (filter !== 'all' && item.category !== filter) {
          return false;
        }
        
        return true;
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [items, query, filter]);
  
  const categories = useMemo(() => {
    return ['all', ...new Set(items.map(item => item.category))];
  }, [items]);
  
  return (
    <div>
      <input
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search..."
      />
      
      <select value={filter} onChange={(e) => setFilter(e.target.value)}>
        {categories.map(cat => (
          <option key={cat} value={cat}>
            {cat.charAt(0).toUpperCase() + cat.slice(1)}
          </option>
        ))}
      </select>
      
      <div>Found {filteredItems.length} items</div>
      
      <ul>
        {filteredItems.map(item => (
          <li key={item.id}>
            {item.name} - {item.category}
          </li>
        ))}
      </ul>
    </div>
  );
}
```

---

## Interview Tips & Best Practices

### General Tips:
1. **Start Simple**: Answer the question directly, then expand
2. **Use Examples**: Concrete examples are better than abstract explanations
3. **Know Trade-offs**: Every solution has pros and cons
4. **Modern React**: Focus on hooks unless asked about classes
5. **Performance**: Don't optimize prematurely, but know how to when needed

### Common Mistakes to Avoid:
1. Over-complicating answers
2. Not mentioning trade-offs
3. Ignoring performance considerations
4. Not knowing when NOT to use a feature
5. Memorizing code without understanding

### What Interviewers Look For:
1. Understanding of fundamentals
2. Problem-solving approach
3. Knowledge of best practices
4. Awareness of trade-offs
5. Practical experience

---

## Quick Reference

### Must-Know Hooks:
- useState, useEffect, useContext
- useCallback, useMemo, useRef
- useReducer (for complex state)

### Must-Know Patterns:
- Component composition
- Custom hooks
- Context for state sharing
- Error boundaries

### Must-Know Performance:
- React.memo
- Code splitting
- Virtual lists for large data
- Proper keys

### Must-Know Concepts:
- Virtual DOM
- Reconciliation
- One-way data flow
- Component lifecycle

---

**End of Guide**

Remember: Understanding WHY is more important than memorizing HOW. 
Focus on fundamentals, practice coding, and you'll do great!

Good luck with your interview! 🚀
