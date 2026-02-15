
# React Hooks - Complete Interview Guide

## Theory & Fundamentals

### What are React Hooks?
Hooks are functions that let you "hook into" React features from functional components. They enable state management and lifecycle features without class components.

### Why were Hooks introduced?
- Simplify component logic
- Enable code reuse between components
- Reduce bundle size
- Easier testing and reasoning about code

## Common Hooks

### 1. useState
**Use Case:** Manage component state
**Syntax:** `const [state, setState] = useState(initialValue)`

**Advantages:**
- Simple state management
- Multiple states in one component
- Functional approach

**Disadvantages:**
- Requires understanding of closure
- Can cause stale closures

### 2. useEffect
**Use Case:** Side effects (API calls, subscriptions, DOM updates)
**Syntax:** `useEffect(() => { }, [dependencies])`

**Advantages:**
- Replaces componentDidMount, componentDidUpdate, componentWillUnmount
- Dependency array for optimization
- Cleaner than lifecycle methods

**Disadvantages:**
- Runs on every render by default
- Complex dependency tracking
- Can cause infinite loops if misused

### 3. useContext
**Use Case:** Share data across components without props drilling
**Syntax:** `const value = useContext(MyContext)`

**Advantages:**
- Avoids prop drilling
- Global state management
- Simple implementation

**Disadvantages:**
- All consumers re-render when context changes
- Not ideal for frequently changing data

### 4. useReducer
**Use Case:** Complex state logic with multiple actions
**Syntax:** `const [state, dispatch] = useReducer(reducer, initialState)`

**Advantages:**
- Better for complex state
- Predictable state updates
- Easier to test

**Disadvantages:**
- More boilerplate than useState
- Learning curve for new developers

### 5. useCallback
**Use Case:** Memoize callback functions
**Syntax:** `const memoizedCallback = useCallback(() => { }, [dependencies])`

**Advantages:**
- Prevents unnecessary re-renders in child components
- Stable function reference

**Disadvantages:**
- Performance overhead if overused
- Increases code complexity

### 6. useMemo
**Use Case:** Memoize expensive computations
**Syntax:** `const memoizedValue = useMemo(() => computeValue(), [dependencies])`

**Advantages:**
- Avoid expensive recalculations
- Performance optimization

**Disadvantages:**
- Add memory overhead
- Premature optimization

### 7. useRef
**Use Case:** Access DOM elements directly or store mutable values
**Syntax:** `const ref = useRef(initialValue)`

**Advantages:**
- Direct DOM access
- Persist values across renders
- Doesn't trigger re-render

**Disadvantages:**
- Can break React's declarative nature
- Not for state management

---

## Interview Questions & Answers

**Q1: What is the difference between useState and useReducer?**
A: useState is for simple state, useReducer for complex logic with multiple actions.

**Q2: Why do we need dependency arrays in useEffect?**
A: To control when effects run and prevent unnecessary executions or infinite loops.

**Q3: What is the difference between useCallback and useMemo?**
A: useCallback memoizes functions, useMemo memoizes computed values.

**Q4: When should you use useRef instead of useState?**
A: Use useRef when you need to access DOM directly or store values that don't trigger re-renders.

**Q5: How do you prevent infinite loops in useEffect?**
A: Always include proper dependencies in the dependency array and avoid omitting required dependencies.

**Q6: What is prop drilling and how do useContext solve it?**
A: Prop drilling is passing props through many intermediate components. useContext allows direct access to values without passing through every level.

**Q7: When should you use useMemo and useCallback?**
A: Use them only when you have genuine performance issues. Measure first to avoid premature optimization.

**Q8: What are custom hooks?**
A: Custom hooks are JavaScript functions that use other hooks. They let you extract component logic into reusable functions.

**Q9: Can you use hooks conditionally?**
A: No. Always call hooks at the top level of your functional component to maintain consistent call order.

**Q10: What is the closure problem in hooks?**
A: Callbacks can capture stale state values if dependencies aren't properly specified in the dependency array.

## Best Practices

- Always specify dependencies in useEffect and useCallback
- Keep custom hooks focused and single-purpose
- Avoid calling hooks conditionally or in loops
- Use React DevTools Profiler to identify performance bottlenecks
- Prefer simplicity: use useState before useReducer
- Never ignore ESLint warnings for hooks

## Resources

- [React Hooks Official Documentation](https://react.dev/reference/react)
- [Hooks API Reference](https://react.dev/reference/react)
- [Custom Hooks Patterns](https://react.dev/learn/reusing-logic-with-custom-hooks)
