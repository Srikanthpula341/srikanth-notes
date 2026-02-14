# React Performance Optimization - Complete Interview Guide

## Table of Contents
1. [Performance Optimization Fundamentals](#performance-optimization-fundamentals)
2. [Code Splitting](#code-splitting)
3. [Lazy Loading](#lazy-loading)
4. [Caching Strategies](#caching-strategies)
5. [Bundle Optimization](#bundle-optimization)
6. [Real-World Scenarios & Interview Questions](#real-world-scenarios)

---

## Performance Optimization Fundamentals

### 1. React Component Optimization

#### React.memo()
**Purpose**: Prevents unnecessary re-renders by memoizing component output.

```jsx
// Without React.memo - re-renders every time parent re-renders
const ExpensiveComponent = ({ data }) => {
  console.log('Rendering ExpensiveComponent');
  return <div>{data.name}</div>;
};

// With React.memo - only re-renders when props change
const OptimizedComponent = React.memo(({ data }) => {
  console.log('Rendering OptimizedComponent');
  return <div>{data.name}</div>;
});

// Custom comparison function
const areEqual = (prevProps, nextProps) => {
  return prevProps.data.id === nextProps.data.id;
};

const CustomMemoComponent = React.memo(
  ({ data }) => <div>{data.name}</div>,
  areEqual
);
```

**Interview Questions**:
- When should you NOT use React.memo?
  - For components that always receive different props
  - For components that render frequently with different data
  - When the cost of comparison outweighs re-render cost

#### useMemo Hook
**Purpose**: Memoizes expensive calculations between renders.

```jsx
import { useMemo, useState } from 'react';

const DataProcessor = ({ items }) => {
  const [filter, setFilter] = useState('');

  // Without useMemo - recalculates on every render
  const processedData = items
    .filter(item => item.name.includes(filter))
    .map(item => ({ ...item, processed: true }))
    .sort((a, b) => a.value - b.value);

  // With useMemo - only recalculates when dependencies change
  const optimizedData = useMemo(() => {
    console.log('Processing data...');
    return items
      .filter(item => item.name.includes(filter))
      .map(item => ({ ...item, processed: true }))
      .sort((a, b) => a.value - b.value);
  }, [items, filter]);

  return <div>{/* render optimizedData */}</div>;
};

// Complex calculation example
const ComplexCalculation = ({ numbers }) => {
  const fibonacci = useMemo(() => {
    const fib = (n) => (n <= 1 ? n : fib(n - 1) + fib(n - 2));
    return numbers.map(num => fib(num));
  }, [numbers]);

  return <div>{fibonacci.join(', ')}</div>;
};
```

**Key Points**:
- Only use for expensive computations
- Don't over-optimize - memoization has overhead
- Dependencies array must include all values used in calculation

#### useCallback Hook
**Purpose**: Memoizes function references to prevent child re-renders.

```jsx
import { useCallback, useState, memo } from 'react';

// Child component that receives callback
const ChildComponent = memo(({ onUpdate, data }) => {
  console.log('Child rendered');
  return <button onClick={() => onUpdate(data)}>Update</button>;
});

const ParentComponent = () => {
  const [count, setCount] = useState(0);
  const [items, setItems] = useState([]);

  // Without useCallback - new function on every render
  const handleUpdate = (data) => {
    setItems(prev => [...prev, data]);
  };

  // With useCallback - same function reference
  const optimizedUpdate = useCallback((data) => {
    setItems(prev => [...prev, data]);
  }, []); // Empty deps - function never changes

  // With dependencies
  const updateWithCount = useCallback((data) => {
    setItems(prev => [...prev, { ...data, count }]);
  }, [count]); // Recreates when count changes

  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>Count: {count}</button>
      <ChildComponent onUpdate={optimizedUpdate} data={{ id: 1 }} />
    </div>
  );
};
```

**useCallback vs useMemo**:
```jsx
// useCallback returns the function itself
const memoizedCallback = useCallback(() => {
  doSomething(a, b);
}, [a, b]);

// useMemo returns the result of the function
const memoizedValue = useMemo(() => {
  return computeExpensiveValue(a, b);
}, [a, b]);

// These are equivalent:
useCallback(fn, deps) === useMemo(() => fn, deps)
```

### 2. Virtual DOM Optimization

#### Key Prop Importance
```jsx
// Bad - using index as key
const BadList = ({ items }) => (
  <ul>
    {items.map((item, index) => (
      <li key={index}>{item.name}</li>
    ))}
  </ul>
);

// Good - using unique identifier
const GoodList = ({ items }) => (
  <ul>
    {items.map((item) => (
      <li key={item.id}>{item.name}</li>
    ))}
  </ul>
);

// Why it matters:
// When items reorder, React can't track them correctly with index keys
const DynamicList = () => {
  const [items, setItems] = useState([
    { id: 1, name: 'Item 1' },
    { id: 2, name: 'Item 2' },
    { id: 3, name: 'Item 3' }
  ]);

  const shuffle = () => {
    setItems(prev => [...prev].sort(() => Math.random() - 0.5));
  };

  return (
    <>
      <button onClick={shuffle}>Shuffle</button>
      <ul>
        {items.map((item) => (
          <li key={item.id}>
            <input type="text" defaultValue={item.name} />
          </li>
        ))}
      </ul>
    </>
  );
};
```

#### Fragment Usage
```jsx
// Avoid unnecessary DOM nodes
const WithDiv = () => (
  <div>
    <ComponentA />
    <ComponentB />
  </div>
);

// Better - no extra DOM node
const WithFragment = () => (
  <>
    <ComponentA />
    <ComponentB />
  </>
);

// When you need keys
const ListWithFragments = ({ groups }) => (
  <ul>
    {groups.map(group => (
      <Fragment key={group.id}>
        <li>{group.title}</li>
        {group.items.map(item => (
          <li key={item.id}>{item.name}</li>
        ))}
      </Fragment>
    ))}
  </ul>
);
```

### 3. State Management Optimization

#### State Colocation
```jsx
// Bad - state at top level causes unnecessary re-renders
const BadApp = () => {
  const [user, setUser] = useState(null);
  const [theme, setTheme] = useState('light');
  const [sidebar, setSidebar] = useState(false);

  return (
    <div>
      <Header theme={theme} />
      <Sidebar isOpen={sidebar} />
      <Content user={user} />
    </div>
  );
};

// Good - state close to where it's used
const GoodApp = () => {
  return (
    <div>
      <HeaderWithTheme />
      <SidebarWithState />
      <ContentWithUser />
    </div>
  );
};

const HeaderWithTheme = () => {
  const [theme, setTheme] = useState('light');
  return <Header theme={theme} onThemeChange={setTheme} />;
};
```

#### Reducer for Complex State
```jsx
import { useReducer } from 'react';

// Complex state with multiple related values
const formReducer = (state, action) => {
  switch (action.type) {
    case 'SET_FIELD':
      return { ...state, [action.field]: action.value };
    case 'SET_ERROR':
      return { ...state, errors: { ...state.errors, [action.field]: action.error } };
    case 'RESET':
      return action.initialState;
    case 'SUBMIT_START':
      return { ...state, isSubmitting: true, errors: {} };
    case 'SUBMIT_SUCCESS':
      return { ...state, isSubmitting: false, isSuccess: true };
    case 'SUBMIT_ERROR':
      return { ...state, isSubmitting: false, errors: action.errors };
    default:
      return state;
  }
};

const OptimizedForm = () => {
  const [state, dispatch] = useReducer(formReducer, {
    name: '',
    email: '',
    errors: {},
    isSubmitting: false,
    isSuccess: false
  });

  const handleChange = (field) => (e) => {
    dispatch({ type: 'SET_FIELD', field, value: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    dispatch({ type: 'SUBMIT_START' });
    try {
      await submitForm(state);
      dispatch({ type: 'SUBMIT_SUCCESS' });
    } catch (error) {
      dispatch({ type: 'SUBMIT_ERROR', errors: error.errors });
    }
  };

  return <form onSubmit={handleSubmit}>{/* form fields */}</form>;
};
```

### 4. Context API Optimization

#### Split Contexts
```jsx
// Bad - single context for everything
const AppContext = createContext();

const AppProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [theme, setTheme] = useState('light');
  const [settings, setSettings] = useState({});

  // Every state change causes all consumers to re-render
  const value = { user, setUser, theme, setTheme, settings, setSettings };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

// Good - separate contexts
const UserContext = createContext();
const ThemeContext = createContext();
const SettingsContext = createContext();

const UserProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  return (
    <UserContext.Provider value={{ user, setUser }}>
      {children}
    </UserContext.Provider>
  );
};

const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState('light');
  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

// Components only re-render when their specific context changes
const Header = () => {
  const { theme } = useContext(ThemeContext); // Only re-renders on theme change
  return <header className={theme}>Header</header>;
};
```

#### Context with useMemo
```jsx
const OptimizedProvider = ({ children }) => {
  const [state, setState] = useState(initialState);

  // Memoize the context value
  const value = useMemo(() => ({
    state,
    updateState: (newState) => setState(newState),
    // Other methods
  }), [state]);

  return <MyContext.Provider value={value}>{children}</MyContext.Provider>;
};

// Split value and dispatch contexts
const StateContext = createContext();
const DispatchContext = createContext();

const SplitContextProvider = ({ children }) => {
  const [state, dispatch] = useReducer(reducer, initialState);

  return (
    <StateContext.Provider value={state}>
      <DispatchContext.Provider value={dispatch}>
        {children}
      </DispatchContext.Provider>
    </StateContext.Provider>
  );
};

// Components only re-render if they use state
const DisplayComponent = () => {
  const state = useContext(StateContext);
  return <div>{state.data}</div>;
};

// This component never re-renders (dispatch doesn't change)
const ActionComponent = () => {
  const dispatch = useContext(DispatchContext);
  return <button onClick={() => dispatch({ type: 'UPDATE' })}>Update</button>;
};
```

---

## Code Splitting

### 1. Route-Based Code Splitting

```jsx
import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

// Eagerly loaded - part of main bundle
import Home from './pages/Home';
import Navigation from './components/Navigation';

// Lazy loaded - separate chunks
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Profile = lazy(() => import('./pages/Profile'));
const Settings = lazy(() => import('./pages/Settings'));
const Admin = lazy(() => import('./pages/Admin'));

// Loading component
const PageLoader = () => (
  <div className="page-loader">
    <div className="spinner" />
    <p>Loading...</p>
  </div>
);

const App = () => {
  return (
    <BrowserRouter>
      <Navigation />
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/admin/*" element={<Admin />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
};

export default App;
```

### 2. Component-Based Code Splitting

```jsx
import { lazy, Suspense, useState } from 'react';

// Heavy components loaded on demand
const Chart = lazy(() => import('./components/Chart'));
const VideoPlayer = lazy(() => import('./components/VideoPlayer'));
const ImageEditor = lazy(() => import('./components/ImageEditor'));

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <div>
      <div className="tabs">
        <button onClick={() => setActiveTab('overview')}>Overview</button>
        <button onClick={() => setActiveTab('charts')}>Charts</button>
        <button onClick={() => setActiveTab('videos')}>Videos</button>
        <button onClick={() => setActiveTab('editor')}>Editor</button>
      </div>

      <div className="content">
        {activeTab === 'overview' && <Overview />}
        
        {activeTab === 'charts' && (
          <Suspense fallback={<div>Loading charts...</div>}>
            <Chart data={chartData} />
          </Suspense>
        )}
        
        {activeTab === 'videos' && (
          <Suspense fallback={<div>Loading player...</div>}>
            <VideoPlayer url={videoUrl} />
          </Suspense>
        )}
        
        {activeTab === 'editor' && (
          <Suspense fallback={<div>Loading editor...</div>}>
            <ImageEditor image={currentImage} />
          </Suspense>
        )}
      </div>
    </div>
  );
};
```

### 3. Library Code Splitting

```jsx
// Split heavy libraries
const HeavyLibraryComponent = lazy(() => 
  import(/* webpackChunkName: "heavy-lib" */ './HeavyComponent')
);

// Dynamic import for libraries
const loadChartLibrary = () => {
  return import('chart.js').then(module => module.default);
};

const ChartComponent = () => {
  const [ChartLib, setChartLib] = useState(null);

  useEffect(() => {
    loadChartLibrary().then(lib => setChartLib(() => lib));
  }, []);

  if (!ChartLib) return <div>Loading chart library...</div>;

  return <ChartLib data={data} />;
};

// Conditional loading
const AdminPanel = () => {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [AdvancedTools, setAdvancedTools] = useState(null);

  const loadAdvancedTools = async () => {
    const module = await import('./AdvancedTools');
    setAdvancedTools(() => module.default);
    setShowAdvanced(true);
  };

  return (
    <div>
      <button onClick={loadAdvancedTools}>
        Show Advanced Tools
      </button>
      {showAdvanced && AdvancedTools && <AdvancedTools />}
    </div>
  );
};
```

### 4. Named Exports with Lazy Loading

```jsx
// When you need specific exports
const MyComponent = lazy(() => 
  import('./Components').then(module => ({
    default: module.SpecificComponent
  }))
);

// Multiple named exports
const loadComponents = async () => {
  const module = await import('./MultipleComponents');
  return {
    ComponentA: module.ComponentA,
    ComponentB: module.ComponentB,
    ComponentC: module.ComponentC
  };
};

// Usage
const App = () => {
  const [components, setComponents] = useState(null);

  useEffect(() => {
    loadComponents().then(setComponents);
  }, []);

  if (!components) return <div>Loading...</div>;

  const { ComponentA, ComponentB, ComponentC } = components;

  return (
    <div>
      <ComponentA />
      <ComponentB />
      <ComponentC />
    </div>
  );
};
```

### 5. Error Boundaries with Code Splitting

```jsx
import { Component, lazy, Suspense } from 'react';

class ErrorBoundary extends Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Code splitting error:', error, errorInfo);
    // Log to error reporting service
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-container">
          <h2>Failed to load component</h2>
          <p>{this.state.error?.message}</p>
          <button onClick={() => window.location.reload()}>
            Reload Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

// Usage with lazy loading
const LazyComponent = lazy(() => import('./HeavyComponent'));

const App = () => (
  <ErrorBoundary>
    <Suspense fallback={<div>Loading...</div>}>
      <LazyComponent />
    </Suspense>
  </ErrorBoundary>
);
```

### 6. Retry Logic for Failed Chunks

```jsx
const retry = (fn, retriesLeft = 3, interval = 1000) => {
  return new Promise((resolve, reject) => {
    fn()
      .then(resolve)
      .catch((error) => {
        setTimeout(() => {
          if (retriesLeft === 1) {
            reject(error);
            return;
          }

          retry(fn, retriesLeft - 1, interval).then(resolve, reject);
        }, interval);
      });
  });
};

// Lazy load with retry
const LazyComponentWithRetry = lazy(() => 
  retry(() => import('./Component'))
);

// More sophisticated retry
const lazyWithRetry = (importFunc, retries = 3) => {
  return lazy(() => {
    const load = async (n = 0) => {
      try {
        return await importFunc();
      } catch (error) {
        if (n < retries) {
          // Wait and retry
          await new Promise(resolve => setTimeout(resolve, 1000 * (n + 1)));
          return load(n + 1);
        }
        throw error;
      }
    };
    return load();
  });
};

const ReliableComponent = lazyWithRetry(
  () => import('./ImportantComponent'),
  5 // retry 5 times
);
```

---

## Lazy Loading

### 1. Image Lazy Loading

```jsx
// Native lazy loading
const LazyImage = ({ src, alt, ...props }) => {
  return (
    <img 
      src={src} 
      alt={alt} 
      loading="lazy"
      {...props}
    />
  );
};

// Intersection Observer approach
import { useEffect, useRef, useState } from 'react';

const AdvancedLazyImage = ({ src, placeholder, alt, threshold = 0.1 }) => {
  const [imageSrc, setImageSrc] = useState(placeholder);
  const [isLoaded, setIsLoaded] = useState(false);
  const imgRef = useRef();

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setImageSrc(src);
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold }
    );

    if (imgRef.current) {
      observer.observe(imgRef.current);
    }

    return () => {
      if (imgRef.current) {
        observer.unobserve(imgRef.current);
      }
    };
  }, [src, threshold]);

  return (
    <img
      ref={imgRef}
      src={imageSrc}
      alt={alt}
      onLoad={() => setIsLoaded(true)}
      style={{
        filter: isLoaded ? 'none' : 'blur(20px)',
        transition: 'filter 0.3s'
      }}
    />
  );
};

// Progressive image loading
const ProgressiveImage = ({ src, placeholder }) => {
  const [currentSrc, setCurrentSrc] = useState(placeholder);

  useEffect(() => {
    const img = new Image();
    img.src = src;
    img.onload = () => setCurrentSrc(src);
  }, [src]);

  return (
    <img
      src={currentSrc}
      style={{
        filter: currentSrc === placeholder ? 'blur(10px)' : 'none',
        transition: 'filter 0.3s'
      }}
    />
  );
};
```

### 2. Infinite Scroll with Lazy Loading

```jsx
import { useState, useEffect, useRef, useCallback } from 'react';

const InfiniteScrollList = () => {
  const [items, setItems] = useState([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const observerTarget = useRef(null);

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;

    setLoading(true);
    try {
      const response = await fetch(`/api/items?page=${page}&limit=20`);
      const newItems = await response.json();
      
      if (newItems.length === 0) {
        setHasMore(false);
      } else {
        setItems(prev => [...prev, ...newItems]);
        setPage(prev => prev + 1);
      }
    } catch (error) {
      console.error('Failed to load items:', error);
    } finally {
      setLoading(false);
    }
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

    if (observerTarget.current) {
      observer.observe(observerTarget.current);
    }

    return () => {
      if (observerTarget.current) {
        observer.unobserve(observerTarget.current);
      }
    };
  }, [observerTarget, loadMore]);

  return (
    <div className="list-container">
      {items.map((item) => (
        <div key={item.id} className="list-item">
          {item.content}
        </div>
      ))}
      
      {loading && <div className="loader">Loading...</div>}
      
      {hasMore && <div ref={observerTarget} style={{ height: '20px' }} />}
      
      {!hasMore && <div className="end-message">No more items</div>}
    </div>
  );
};
```

### 3. Virtual Scrolling (Windowing)

```jsx
import { useState, useRef, useEffect } from 'react';

const VirtualList = ({ items, itemHeight, containerHeight }) => {
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef(null);

  const visibleStart = Math.floor(scrollTop / itemHeight);
  const visibleEnd = Math.ceil((scrollTop + containerHeight) / itemHeight);
  
  const visibleItems = items.slice(
    Math.max(0, visibleStart - 5), // Buffer above
    Math.min(items.length, visibleEnd + 5) // Buffer below
  );

  const totalHeight = items.length * itemHeight;
  const offsetY = Math.max(0, visibleStart - 5) * itemHeight;

  const handleScroll = (e) => {
    setScrollTop(e.target.scrollTop);
  };

  return (
    <div
      ref={containerRef}
      style={{
        height: containerHeight,
        overflow: 'auto',
        position: 'relative'
      }}
      onScroll={handleScroll}
    >
      <div style={{ height: totalHeight, position: 'relative' }}>
        <div style={{ transform: `translateY(${offsetY}px)` }}>
          {visibleItems.map((item, index) => (
            <div
              key={visibleStart + index}
              style={{
                height: itemHeight,
                display: 'flex',
                alignItems: 'center',
                borderBottom: '1px solid #ddd'
              }}
            >
              {item.content}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// Using react-window library (recommended)
import { FixedSizeList } from 'react-window';

const OptimizedVirtualList = ({ items }) => {
  const Row = ({ index, style }) => (
    <div style={style} className="row">
      {items[index].content}
    </div>
  );

  return (
    <FixedSizeList
      height={600}
      itemCount={items.length}
      itemSize={50}
      width="100%"
    >
      {Row}
    </FixedSizeList>
  );
};
```

### 4. Modal/Dialog Lazy Loading

```jsx
import { useState, lazy, Suspense } from 'react';

const LazyModal = lazy(() => import('./Modal'));
const LazyUserProfile = lazy(() => import('./UserProfile'));
const LazySettings = lazy(() => import('./Settings'));

const App = () => {
  const [activeModal, setActiveModal] = useState(null);

  const modals = {
    profile: LazyUserProfile,
    settings: LazySettings,
    generic: LazyModal
  };

  const ModalComponent = activeModal ? modals[activeModal] : null;

  return (
    <div>
      <button onClick={() => setActiveModal('profile')}>
        Open Profile
      </button>
      <button onClick={() => setActiveModal('settings')}>
        Open Settings
      </button>

      {ModalComponent && (
        <Suspense fallback={<div>Loading modal...</div>}>
          <ModalComponent onClose={() => setActiveModal(null)} />
        </Suspense>
      )}
    </div>
  );
};
```

### 5. Lazy Loading with Preloading

```jsx
// Preload on hover
const PreloadableLink = ({ to, children }) => {
  const [Component, setComponent] = useState(null);

  const preload = () => {
    import(`./pages/${to}`).then(module => {
      setComponent(() => module.default);
    });
  };

  return (
    <a 
      href={to} 
      onMouseEnter={preload}
      onFocus={preload}
    >
      {children}
    </a>
  );
};

// Preload after initial render
const Dashboard = () => {
  useEffect(() => {
    // Preload components that will likely be needed
    const preloadComponents = async () => {
      await Promise.all([
        import('./components/Chart'),
        import('./components/DataTable'),
        import('./components/UserProfile')
      ]);
    };

    // Preload after a delay to not block initial render
    const timer = setTimeout(preloadComponents, 2000);
    return () => clearTimeout(timer);
  }, []);

  return <div>Dashboard Content</div>;
};

// Preload on interaction intent
const intelligentPreload = (componentPath) => {
  let preloaded = false;
  let componentModule = null;

  const preload = () => {
    if (preloaded) return Promise.resolve(componentModule);
    
    preloaded = true;
    return import(componentPath).then(module => {
      componentModule = module;
      return module;
    });
  };

  const LazyComponent = lazy(() => {
    if (componentModule) return Promise.resolve(componentModule);
    return preload();
  });

  return { LazyComponent, preload };
};

const { LazyComponent: HeavyChart, preload: preloadChart } = 
  intelligentPreload('./HeavyChart');

const ChartPage = () => {
  return (
    <div>
      <button 
        onMouseEnter={preloadChart}
        onClick={() => {/* show chart */}}
      >
        Show Chart
      </button>
      <Suspense fallback={<div>Loading...</div>}>
        <HeavyChart />
      </Suspense>
    </div>
  );
};
```

---

## Caching Strategies

### 1. Memoization Caching

```jsx
// Custom memoization hook
const useMemoizedValue = (computeFn, deps) => {
  const cache = useRef(new Map());
  const depsKey = JSON.stringify(deps);

  if (cache.current.has(depsKey)) {
    return cache.current.get(depsKey);
  }

  const value = computeFn();
  cache.current.set(depsKey, value);

  // Limit cache size
  if (cache.current.size > 100) {
    const firstKey = cache.current.keys().next().value;
    cache.current.delete(firstKey);
  }

  return value;
};

// Memoize API responses
const useCachedAPI = (url, options = {}) => {
  const cache = useRef(new Map());
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const cacheKey = `${url}-${JSON.stringify(options)}`;

    // Check cache first
    if (cache.current.has(cacheKey)) {
      setData(cache.current.get(cacheKey));
      return;
    }

    setLoading(true);
    fetch(url, options)
      .then(res => res.json())
      .then(result => {
        cache.current.set(cacheKey, result);
        setData(result);
      })
      .catch(err => setError(err))
      .finally(() => setLoading(false));
  }, [url, options]);

  return { data, loading, error };
};
```

### 2. Browser Caching (Service Worker)

```jsx
// service-worker.js
const CACHE_NAME = 'my-app-cache-v1';
const urlsToCache = [
  '/',
  '/static/css/main.css',
  '/static/js/main.js',
  '/static/js/bundle.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(urlsToCache);
    })
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      // Cache hit - return response
      if (response) {
        return response;
      }

      return fetch(event.request).then((response) => {
        // Check if valid response
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }

        // Clone the response
        const responseToCache = response.clone();

        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });

        return response;
      });
    })
  );
});

// Register in React app
// index.js or App.js
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/service-worker.js')
      .then(registration => {
        console.log('SW registered:', registration);
      })
      .catch(error => {
        console.log('SW registration failed:', error);
      });
  });
}
```

### 3. localStorage/sessionStorage Caching

```jsx
// Utility for storage caching
const StorageCache = {
  set: (key, value, expiryMinutes = 60) => {
    const item = {
      value,
      expiry: Date.now() + expiryMinutes * 60 * 1000
    };
    localStorage.setItem(key, JSON.stringify(item));
  },

  get: (key) => {
    const itemStr = localStorage.getItem(key);
    if (!itemStr) return null;

    const item = JSON.parse(itemStr);
    if (Date.now() > item.expiry) {
      localStorage.removeItem(key);
      return null;
    }

    return item.value;
  },

  remove: (key) => {
    localStorage.removeItem(key);
  },

  clear: () => {
    localStorage.clear();
  }
};

// Hook for cached data
const useCachedState = (key, initialValue, expiryMinutes = 60) => {
  const [value, setValue] = useState(() => {
    const cached = StorageCache.get(key);
    return cached !== null ? cached : initialValue;
  });

  useEffect(() => {
    StorageCache.set(key, value, expiryMinutes);
  }, [key, value, expiryMinutes]);

  return [value, setValue];
};

// Usage
const UserProfile = () => {
  const [userData, setUserData] = useCachedState('user-profile', null, 30);

  useEffect(() => {
    if (!userData) {
      fetchUserData().then(setUserData);
    }
  }, [userData]);

  return <div>{userData?.name}</div>;
};
```

### 4. React Query / SWR Caching

```jsx
// Using React Query
import { useQuery, QueryClient, QueryClientProvider } from '@tanstack/react-query';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: false,
      retry: 3
    }
  }
});

const App = () => (
  <QueryClientProvider client={queryClient}>
    <YourApp />
  </QueryClientProvider>
);

// Component using query
const UserList = () => {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['users'],
    queryFn: () => fetch('/api/users').then(res => res.json()),
    staleTime: 5 * 60 * 1000
  });

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <div>
      <button onClick={() => refetch()}>Refresh</button>
      {data.map(user => <UserCard key={user.id} user={user} />)}
    </div>
  );
};

// Using SWR
import useSWR from 'swr';

const fetcher = url => fetch(url).then(res => res.json());

const Profile = () => {
  const { data, error, mutate } = useSWR('/api/user', fetcher, {
    revalidateOnFocus: false,
    revalidateOnReconnect: true,
    dedupingInterval: 5000
  });

  if (error) return <div>Failed to load</div>;
  if (!data) return <div>Loading...</div>;

  return (
    <div>
      <h1>{data.name}</h1>
      <button onClick={() => mutate()}>Refresh</button>
    </div>
  );
};
```

### 5. HTTP Caching Headers

```jsx
// API routes with caching headers (Next.js example)
export async function GET(request) {
  const data = await fetchData();

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      // Cache for 1 hour, revalidate in background
      'Cache-Control': 'public, s-maxage=3600, stale-while-revalidate=86400'
    }
  });
}

// Fetch with cache control
const fetchWithCache = async (url, options = {}) => {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Cache-Control': 'max-age=3600'
    }
  });

  return response.json();
};

// Custom fetch hook with caching
const useFetchWithCache = (url) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();

    fetch(url, {
      signal: controller.signal,
      headers: {
        'Cache-Control': 'max-age=3600'
      }
    })
      .then(res => res.json())
      .then(setData)
      .catch(err => {
        if (err.name !== 'AbortError') {
          console.error(err);
        }
      })
      .finally(() => setLoading(false));

    return () => controller.abort();
  }, [url]);

  return { data, loading };
};
```

### 6. Component-Level Caching

```jsx
// Cache expensive computations across component instances
const computationCache = new Map();

const ExpensiveComponent = ({ inputData }) => {
  const cacheKey = JSON.stringify(inputData);

  const result = useMemo(() => {
    if (computationCache.has(cacheKey)) {
      console.log('Using cached result');
      return computationCache.get(cacheKey);
    }

    console.log('Computing new result');
    const computed = expensiveOperation(inputData);
    computationCache.set(cacheKey, computed);

    // Limit cache size
    if (computationCache.size > 50) {
      const firstKey = computationCache.keys().next().value;
      computationCache.delete(firstKey);
    }

    return computed;
  }, [cacheKey]);

  return <div>{result}</div>;
};

// LRU Cache implementation
class LRUCache {
  constructor(capacity) {
    this.capacity = capacity;
    this.cache = new Map();
  }

  get(key) {
    if (!this.cache.has(key)) return undefined;
    
    const value = this.cache.get(key);
    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.capacity) {
      // Remove least recently used (first item)
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  clear() {
    this.cache.clear();
  }
}

const imageCache = new LRUCache(100);

const CachedImage = ({ src }) => {
  const [imageSrc, setImageSrc] = useState(imageCache.get(src));

  useEffect(() => {
    if (!imageSrc) {
      const img = new Image();
      img.src = src;
      img.onload = () => {
        imageCache.set(src, src);
        setImageSrc(src);
      };
    }
  }, [src, imageSrc]);

  return imageSrc ? <img src={imageSrc} alt="" /> : <div>Loading...</div>;
};
```

---

## Bundle Optimization

### 1. Webpack Configuration

```javascript
// webpack.config.js
const path = require('path');
const webpack = require('webpack');
const TerserPlugin = require('terser-webpack-plugin');
const CompressionPlugin = require('compression-webpack-plugin');
const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;

module.exports = {
  mode: 'production',
  entry: {
    main: './src/index.js',
    vendor: ['react', 'react-dom']
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].[contenthash].js',
    chunkFilename: '[name].[contenthash].chunk.js',
    clean: true
  },
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          compress: {
            drop_console: true, // Remove console.logs
            drop_debugger: true
          },
          mangle: true,
          output: {
            comments: false
          }
        },
        extractComments: false
      })
    ],
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        // Vendor bundle for node_modules
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendor',
          priority: 10,
          reuseExistingChunk: true
        },
        // React bundle
        react: {
          test: /[\\/]node_modules[\\/](react|react-dom)[\\/]/,
          name: 'react',
          priority: 20
        },
        // Common shared code
        common: {
          minChunks: 2,
          priority: 5,
          reuseExistingChunk: true,
          enforce: true
        },
        // CSS
        styles: {
          name: 'styles',
          test: /\.css$/,
          chunks: 'all',
          enforce: true
        }
      }
    },
    runtimeChunk: 'single',
    moduleIds: 'deterministic'
  },
  plugins: [
    // Gzip compression
    new CompressionPlugin({
      filename: '[path][base].gz',
      algorithm: 'gzip',
      test: /\.(js|css|html|svg)$/,
      threshold: 8192,
      minRatio: 0.8
    }),
    // Brotli compression
    new CompressionPlugin({
      filename: '[path][base].br',
      algorithm: 'brotliCompress',
      test: /\.(js|css|html|svg)$/,
      threshold: 8192,
      minRatio: 0.8
    }),
    // Bundle analysis
    new BundleAnalyzerPlugin({
      analyzerMode: 'static',
      openAnalyzer: false,
      reportFilename: 'bundle-report.html'
    }),
    // Define environment variables
    new webpack.DefinePlugin({
      'process.env.NODE_ENV': JSON.stringify('production')
    })
  ],
  resolve: {
    extensions: ['.js', '.jsx'],
    alias: {
      '@components': path.resolve(__dirname, 'src/components'),
      '@utils': path.resolve(__dirname, 'src/utils')
    }
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', { modules: false }],
              '@babel/preset-react'
            ],
            plugins: [
              '@babel/plugin-proposal-class-properties',
              // Remove PropTypes in production
              ['transform-react-remove-prop-types', { removeImport: true }]
            ]
          }
        }
      }
    ]
  },
  performance: {
    maxEntrypointSize: 512000,
    maxAssetSize: 512000,
    hints: 'warning'
  }
};
```

### 2. Dynamic Imports & Prefetching

```jsx
// Prefetch - loads during idle time
import(/* webpackPrefetch: true */ './OptionalComponent');

// Preload - loads in parallel with parent
import(/* webpackPreload: true */ './CriticalComponent');

// Named chunks
const AdminPanel = lazy(() => 
  import(/* webpackChunkName: "admin" */ './AdminPanel')
);

const Analytics = lazy(() => 
  import(/* webpackChunkName: "analytics" */ './Analytics')
);

// Magic comments for optimization
const HeavyLibrary = lazy(() =>
  import(
    /* webpackChunkName: "heavy-lib" */
    /* webpackPrefetch: true */
    './HeavyLibrary'
  )
);
```

### 3. Tree Shaking

```jsx
// Bad - imports entire library
import _ from 'lodash';
import moment from 'moment';

// Good - import only what you need
import debounce from 'lodash/debounce';
import sortBy from 'lodash/sortBy';

// Even better - use lodash-es (ES modules)
import { debounce, sortBy } from 'lodash-es';

// Date library alternatives
import dayjs from 'dayjs'; // Much smaller than moment
import { format } from 'date-fns'; // Tree-shakeable

// Configure babel to help with tree shaking
// babel.config.js
module.exports = {
  presets: [
    ['@babel/preset-env', {
      modules: false, // Keep ES modules for tree shaking
      useBuiltIns: 'usage',
      corejs: 3
    }]
  ],
  plugins: [
    // Transform imports for better tree shaking
    ['babel-plugin-import', {
      libraryName: 'antd',
      style: true
    }]
  ]
};

// package.json sideEffects
{
  "name": "my-app",
  "sideEffects": [
    "*.css",
    "*.scss",
    "./src/polyfills.js"
  ]
}
```

### 4. Analyzing Bundle Size

```javascript
// Install webpack-bundle-analyzer
// npm install --save-dev webpack-bundle-analyzer

// Add to webpack config
const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');

plugins: [
  new BundleAnalyzerPlugin({
    analyzerMode: 'static',
    reportFilename: 'bundle-report.html',
    openAnalyzer: true
  })
]

// Or use source-map-explorer
// npm install --save-dev source-map-explorer

// package.json
{
  "scripts": {
    "analyze": "source-map-explorer 'build/static/js/*.js'"
  }
}
```

```jsx
// Measure component render size
import { Profiler } from 'react';

const onRenderCallback = (
  id,
  phase,
  actualDuration,
  baseDuration,
  startTime,
  commitTime
) => {
  console.log(`${id}'s ${phase} phase:`);
  console.log(`Actual time: ${actualDuration}ms`);
  console.log(`Base time: ${baseDuration}ms`);
};

const App = () => (
  <Profiler id="App" onRender={onRenderCallback}>
    <Navigation />
    <Main />
    <Footer />
  </Profiler>
);
```

### 5. Code Splitting Strategies

```jsx
// Route-based splitting
const routes = [
  {
    path: '/',
    component: lazy(() => import('./pages/Home'))
  },
  {
    path: '/about',
    component: lazy(() => import('./pages/About'))
  },
  {
    path: '/dashboard',
    component: lazy(() => import('./pages/Dashboard'))
  }
];

// Feature-based splitting
const features = {
  chat: lazy(() => import('./features/Chat')),
  notifications: lazy(() => import('./features/Notifications')),
  settings: lazy(() => import('./features/Settings'))
};

// Library-based splitting
const ChartComponent = lazy(() => {
  return Promise.all([
    import('chart.js'),
    import('./ChartWrapper')
  ]).then(([chartjs, wrapper]) => ({
    default: wrapper.default
  }));
});

// Conditional splitting
const getEditor = (type) => {
  switch(type) {
    case 'rich':
      return import('./RichTextEditor');
    case 'markdown':
      return import('./MarkdownEditor');
    case 'code':
      return import('./CodeEditor');
    default:
      return import('./BasicEditor');
  }
};

const Editor = ({ type }) => {
  const [EditorComponent, setEditorComponent] = useState(null);

  useEffect(() => {
    getEditor(type).then(module => {
      setEditorComponent(() => module.default);
    });
  }, [type]);

  if (!EditorComponent) return <div>Loading editor...</div>;

  return <EditorComponent />;
};
```

### 6. Asset Optimization

```javascript
// Image optimization with webpack
module.exports = {
  module: {
    rules: [
      {
        test: /\.(png|jpg|jpeg|gif)$/i,
        type: 'asset',
        parser: {
          dataUrlCondition: {
            maxSize: 8 * 1024 // 8kb - inline smaller images
          }
        },
        generator: {
          filename: 'images/[name].[hash][ext]'
        }
      },
      {
        test: /\.svg$/,
        use: ['@svgr/webpack', 'url-loader']
      }
    ]
  },
  plugins: [
    new ImageMinimizerPlugin({
      minimizer: {
        implementation: ImageMinimizerPlugin.imageminMinify,
        options: {
          plugins: [
            ['gifsicle', { interlaced: true }],
            ['jpegtran', { progressive: true }],
            ['optipng', { optimizationLevel: 5 }],
            ['svgo', {
              plugins: [
                {
                  name: 'removeViewBox',
                  active: false
                }
              ]
            }]
          ]
        }
      }
    })
  ]
};
```

```jsx
// React component for optimized images
const OptimizedImage = ({ src, alt, width, height }) => {
  const [loaded, setLoaded] = useState(false);

  return (
    <picture>
      <source 
        srcSet={`${src}.webp`} 
        type="image/webp" 
      />
      <source 
        srcSet={`${src}.jpg`} 
        type="image/jpeg" 
      />
      <img
        src={`${src}.jpg`}
        alt={alt}
        width={width}
        height={height}
        loading="lazy"
        onLoad={() => setLoaded(true)}
        style={{
          opacity: loaded ? 1 : 0,
          transition: 'opacity 0.3s'
        }}
      />
    </picture>
  );
};
```

### 7. CSS Optimization

```javascript
// webpack.config.js
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const CssMinimizerPlugin = require('css-minimizer-webpack-plugin');

module.exports = {
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [
          MiniCssExtractPlugin.loader,
          'css-loader',
          'postcss-loader'
        ]
      },
      {
        test: /\.scss$/,
        use: [
          MiniCssExtractPlugin.loader,
          'css-loader',
          'postcss-loader',
          'sass-loader'
        ]
      }
    ]
  },
  plugins: [
    new MiniCssExtractPlugin({
      filename: '[name].[contenthash].css',
      chunkFilename: '[id].[contenthash].css'
    })
  ],
  optimization: {
    minimizer: [
      new CssMinimizerPlugin({
        minimizerOptions: {
          preset: [
            'default',
            {
              discardComments: { removeAll: true }
            }
          ]
        }
      })
    ]
  }
};

// postcss.config.js
module.exports = {
  plugins: [
    require('autoprefixer'),
    require('cssnano')({
      preset: 'default'
    })
  ]
};
```

```jsx
// CSS-in-JS optimization
import styled from 'styled-components';

// Bad - creates new styled component on every render
const BadComponent = ({ color }) => {
  const StyledDiv = styled.div`
    color: ${color};
  `;
  return <StyledDiv>Content</StyledDiv>;
};

// Good - define outside component
const StyledDiv = styled.div`
  color: ${props => props.color};
`;

const GoodComponent = ({ color }) => {
  return <StyledDiv color={color}>Content</StyledDiv>;
};

// Use CSS modules for better code splitting
// styles.module.css
.container {
  padding: 20px;
}

// Component.jsx
import styles from './styles.module.css';

const Component = () => (
  <div className={styles.container}>Content</div>
);
```

---

## Real-World Scenarios & Interview Questions

### Scenario 1: Large List Performance

**Problem**: Rendering 10,000 items causes performance issues.

**Solution**:
```jsx
import { FixedSizeList } from 'react-window';

const VirtualizedList = ({ items }) => {
  const Row = ({ index, style }) => (
    <div style={style}>
      <ItemCard item={items[index]} />
    </div>
  );

  return (
    <FixedSizeList
      height={800}
      itemCount={items.length}
      itemSize={120}
      width="100%"
    >
      {Row}
    </FixedSizeList>
  );
};
```

**Interview Answer**: "I would use virtualization with react-window or react-virtualized. This only renders visible items plus a small buffer, reducing DOM nodes from 10,000 to maybe 20-30. For a 50-item viewport, this means 99.5% fewer DOM operations."

### Scenario 2: Heavy Dashboard with Multiple Charts

**Problem**: Dashboard loads slowly with all charts.

**Solution**:
```jsx
const Dashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');

  const LazyChart = lazy(() => import('./Charts'));
  const LazyDataTable = lazy(() => import('./DataTable'));
  const LazyMap = lazy(() => import('./Map'));

  return (
    <div>
      <Tabs onChange={setActiveTab} />
      <Suspense fallback={<ChartSkeleton />}>
        {activeTab === 'charts' && <LazyChart />}
        {activeTab === 'data' && <LazyDataTable />}
        {activeTab === 'map' && <LazyMap />}
      </Suspense>
    </div>
  );
};
```

**Interview Answer**: "I would implement code splitting for each chart type and lazy load them based on the active tab. Additionally, I'd use React.memo for chart components since they're expensive to render, and implement useMemo for data transformations. For the initial load, I'd show skeleton screens instead of spinners."

### Scenario 3: Form with Many Fields

**Problem**: Form re-renders on every keystroke.

**Solution**:
```jsx
import { useForm } from 'react-hook-form';

const OptimizedForm = () => {
  const { register, handleSubmit, formState: { errors } } = useForm({
    mode: 'onBlur' // Validate on blur, not on change
  });

  const onSubmit = useCallback((data) => {
    submitFormData(data);
  }, []);

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('name')} />
      <input {...register('email')} />
      {/* More fields */}
    </form>
  );
};

// Or with manual optimization
const ManualOptimizedForm = () => {
  const [formData, setFormData] = useState({});

  const handleChange = useCallback((field) => (e) => {
    setFormData(prev => ({ ...prev, [field]: e.target.value }));
  }, []);

  return (
    <form>
      <FormField onChange={handleChange('name')} />
      <FormField onChange={handleChange('email')} />
    </form>
  );
};

const FormField = memo(({ onChange, ...props }) => (
  <input onChange={onChange} {...props} />
));
```

**Interview Answer**: "For forms with many fields, I'd use react-hook-form which uses uncontrolled components and ref-based validation, minimizing re-renders. If using controlled components, I'd memoize change handlers with useCallback and wrap input components with React.memo. I'd also validate on blur instead of on change to reduce computation."

### Scenario 4: Real-Time Data Updates

**Problem**: WebSocket updates cause entire app to re-render.

**Solution**:
```jsx
const WebSocketProvider = ({ children }) => {
  const [data, setData] = useState({});
  const listeners = useRef(new Map());

  useEffect(() => {
    const ws = new WebSocket('wss://api.example.com');

    ws.onmessage = (event) => {
      const update = JSON.parse(event.data);
      
      // Only update specific data slice
      setData(prev => ({
        ...prev,
        [update.id]: update.value
      }));

      // Notify specific listeners
      listeners.current.get(update.id)?.forEach(callback => {
        callback(update.value);
      });
    };

    return () => ws.close();
  }, []);

  const subscribe = useCallback((id, callback) => {
    if (!listeners.current.has(id)) {
      listeners.current.set(id, new Set());
    }
    listeners.current.get(id).add(callback);

    return () => {
      listeners.current.get(id)?.delete(callback);
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{ data, subscribe }}>
      {children}
    </WebSocketContext.Provider>
  );
};

const StockTicker = ({ symbol }) => {
  const { subscribe } = useContext(WebSocketContext);
  const [price, setPrice] = useState(0);

  useEffect(() => {
    return subscribe(symbol, setPrice);
  }, [symbol, subscribe]);

  return <div>{symbol}: ${price}</div>;
};
```

**Interview Answer**: "I'd implement a subscription-based system where components only listen to specific data they need. Using a Map of listeners, each component subscribes to its data slice. When WebSocket updates arrive, only affected components re-render. I'd also consider using a state management library like Zustand with selectors for more complex scenarios."

### Common Interview Questions & Answers

#### Q1: When would you use React.memo vs useMemo vs useCallback?

**Expected Answer**: "React.memo is for preventing component re-renders when props haven't changed. useMemo is for memoizing expensive calculations within a component. useCallback is for memoizing function references, typically passed as props to child components."

**Detailed Explanation**:
- **React.memo**: HOC that prevents re-renders if props are identical
  - Best for: Child components that render expensive UI
  - Cost: Prop comparison overhead
  - Example: List item components that receive large objects

- **useMemo**: Hook that caches computed values
  - Best for: Expensive computations (filtering, sorting, calculations)
  - Cost: Memory + comparison overhead
  - Example: Processed data, derived state, filtered arrays

- **useCallback**: Hook that caches function references
  - Best for: Functions passed to child components wrapped in React.memo
  - Cost: Memory overhead
  - Example: Event handlers, API calls, data mutations

**Real Code Comparison**:
```jsx
// React.memo - prevent re-render
const UserCard = React.memo(({ user }) => {
  console.log('UserCard rendered');
  return <div>{user.name}</div>;
});

// useMemo - cache computation
const filteredUsers = useMemo(() => {
  return users.filter(u => u.age > 18).sort((a, b) => a.name.localeCompare(b.name));
}, [users]);

// useCallback - cache function
const handleDelete = useCallback((id) => {
  setUsers(u => u.filter(x => x.id !== id));
}, []); // Empty deps = never recreates
```

**Follow-up Questions to Prepare For**:
- "What's the performance cost of over-memoizing?"
  - Answer: Each memoization has overhead. Only memoize when actual benefit is proven.
- "Can you over-use these hooks?"
  - Answer: Yes! Simple components don't need memoization. Profile first.
- "How do you decide what should go in the dependency array?"
  - Answer: All values from outside the hook used inside it. Use exhaustive-deps linter rule.

---

#### Q2: How do you decide what to code split?

**Expected Answer**: "I follow this priority: First, route-based splitting for different pages. Second, split heavy libraries like charts or rich text editors. Third, split features behind authentication or user permissions. Fourth, split rarely-used features like admin panels or advanced settings. I always measure with webpack-bundle-analyzer to verify impact."

**Prioritization Strategy**:

```
Priority 1: Routes (Different pages users navigate to)
  - Dashboard, Profile, Settings pages
  - Impact: Highest - users often only visit 1-2 pages
  - Implementation: Route-based lazy loading with Suspense

Priority 2: Heavy Libraries (Large third-party packages)
  - Charts (chart.js, recharts) = 150-300kb
  - Editors (monaco, ace) = 500kb+
  - Maps (mapbox, google-maps) = 200-400kb
  - Impact: High - critical performance gain
  - Implementation: Lazy load on component mount or user interaction

Priority 3: Feature Gates (Behind user permissions)
  - Admin panels for non-admin users  
  - Premium features for free users
  - Beta features
  - Impact: Medium - reduces initial load for most users
  - Implementation: Conditional lazy loading based on user role

Priority 4: Rarely Used Features
  - Advanced settings
  - Export/Import functionality
  - Help/Tutorial components
  - Impact: Medium-Low - occasional use
  - Implementation: Lazy load on first interaction
```

**Decision Making Framework**:
```jsx
const shouldCodeSplit = (component) => {
  const checks = [
    component.bundleSize > 50 * 1024,           // > 50kb
    !component.usedOnInitialLoad,                // Not critical
    component.externalDependencies > 2,          // Has dependencies
    component.notAllUsersNeed                    // Conditional
  ];
  return checks.filter(Boolean).length >= 2;
};
```

**Common Mistakes to Avoid**:
- Splitting too many small components (creates too many chunks)
- Not measuring the actual impact
- Splitting code users need immediately
- Creating chunks larger than the main bundle

**Follow-up Questions**:
- "How do you handle preloading of split chunks?"
  - Answer: Use link prefetch tags or preload on hover/interaction
- "What's too many code splits?"
  - Answer: Each chunk has overhead. Aim for 3-10 chunks total.
- "How do you handle failed chunk loading?"
  - Answer: Implement error boundaries and retry logic

---

#### Q3: What's your approach to caching in a React application?

**Expected Answer**: "I use a layered approach: Browser caching via HTTP headers for static assets, service workers for offline support, React Query or SWR for API response caching, useMemo for expensive computations, and localStorage with expiry for user preferences."

**Caching Layer Strategy**:

```
1. Component Cache (useMemo)
   └─ Duration: Component lifetime
   └─ Cost: Memory

2. Browser Cache (localStorage/sessionStorage)
   └─ Duration: User preference (persistent or session)
   └─ Cost: 5-10MB limit

3. API Cache (React Query/SWR)
   └─ Duration: 5-10 minutes (stale time)
   └─ Cost: Memory + smart invalidation

4. Service Worker Cache
   └─ Duration: Permanent (with versioning)
   └─ Cost: Disk space

5. CDN Cache
   └─ Duration: 1 year for versioned assets
   └─ Cost: Network

6. Browser HTTP Cache
   └─ Duration: Configured via headers
   └─ Cost: Disk
```

**Decision Matrix**:

| Data Type | Cache Type | Duration | When to Use |
|-----------|-----------|----------|-------------|
| Static assets | HTTP + CDN | 1 year | Always |
| User config | localStorage | Permanent | User preferences |
| API data | React Query | 5-10 min | Frequently fetched data |
| Calculations | useMemo | Component life | Heavy computations |
| Offline content | Service Worker | Permanent | Critical pages |

**Follow-up Questions**:
- "How do you handle cache invalidation?"
  - Answer: Use queryClient.invalidateQueries() after mutations
- "When should you NOT cache?"
  - Answer: Sensitive data, frequently changing data, user-specific content
- "How do you test caching?"
  - Answer: Use Network tab in DevTools, throttle in Chrome DevTools, mock service worker

---

#### Q4: How would you optimize a React app that's already built?

**Expected Answer**: "First, I'd profile with React DevTools Profiler to identify slow components. Second, run webpack-bundle-analyzer to find large dependencies. Third, check for unnecessary re-renders using why-did-you-render. Fourth, implement React.memo on expensive components. Fifth, add code splitting. Sixth, optimize images. Finally, measure the impact with Lighthouse."

**Step-by-Step Optimization Process**:

```
[ ] 1. MEASURE BASELINE
    └─ Tools: Lighthouse, Chrome DevTools
    └─ Metrics: FCP, LCP, TTI, CLS, FID

[ ] 2. IDENTIFY PROBLEMS
    ├─ React DevTools Profiler → Slow components
    ├─ webpack-bundle-analyzer → Large dependencies
    ├─ why-did-you-render → Unnecessary re-renders
    └─ Chrome DevTools Performance → Long tasks

[ ] 3. PRIORITIZE (Impact vs Effort)
    ├─ High impact, low effort → Do first
    └─ High impact, high effort → Plan for future

[ ] 4. IMPLEMENT (Make changes)
    ├─ React.memo on expensive components
    ├─ Code splitting on routes/features
    ├─ useMemo on expensive calculations
    └─ useCallback on frequently passed functions

[ ] 5. MEASURE AGAIN (Verify improvement)
    ├─ Compare after each change
    └─ Continue if significant improvement
```

**Common Issues & Quick Fixes**:

| Issue | Detection | Fix | Impact |
|-------|-----------|-----|--------|
| Large dependencies | webpack-bundle-analyzer | Replace with smaller lib | High |
| Unnecessary re-renders | why-did-you-render | Add React.memo | High |
| Expensive calculations | React Profiler | Add useMemo | High |
| Missing code splitting | Bundle > 1MB | Split by route | High |
| Unoptimized images | Lighthouse | Use WebP, compression | High |
| Slow API calls | Performance tab | Add caching | Medium |
| Large context | why-did-you-render | Split contexts | Medium |

**Follow-up Questions**:
- "How do you decide which metrics to focus on?"
  - Answer: Core Web Vitals (LCP, FID, CLS) matter most for UX
- "What's a realistic performance improvement?"
  - Answer: 20-40% typical, 50%+ is excellent
- "How often should you optimize?"
  - Answer: After major features, monthly audits minimum

---

#### Q5: Explain tree shaking and how to ensure it works.

**Expected Answer**: "Tree shaking removes unused code from the final bundle. To ensure it works: First, use ES6 imports/exports (not CommonJS). Second, set 'modules: false' in babel config. Third, use named imports. Fourth, configure package.json 'sideEffects'. Fifth, use webpack production mode."

**How Tree Shaking Works**:

1. **Webpack analyzes imports statically** at build time
2. **Marks used exports** in dependency graph
3. **Removes unused exports** from final bundle
4. **Minifier cleans up** dead code

**Requirements for Tree Shaking**:

```jsx
// ✗ BREAKS Tree Shaking (CommonJS)
const _ = require('lodash');

// ✓ WORKS (ES6 modules)
import { debounce } from 'lodash-es';

// ✓ WORKS (named import)
import debounce from 'lodash-es/debounce';

// ✗ BREAKS (default import with large library)
import lodash from 'lodash'; // Imports everything!
```

**Setup Configuration**:

```javascript
// 1. babel.config.js - Keep ES modules
module.exports = {
  presets: [
    ['@babel/preset-env', { modules: false }]  // ← IMPORTANT
  ]
};

// 2. webpack.config.js - Production mode
module.exports = {
  mode: 'production',  // ← IMPORTANT: Enables tree shaking
  optimization: {
    usedExports: true,
    sideEffects: false
  }
};

// 3. package.json - Declare side effects
{
  "sideEffects": ["*.css", "./src/polyfills.js"]
}
```

**Real World Examples**:

```jsx
// EXPENSIVE (150kb+)
import moment from 'moment';  // Only use 1 function

// CHEAP (2kb)
import dayjs from 'dayjs';  // Small library

// EXPENSIVE (70kb)
import _ from 'lodash';

// CHEAP (1kb)
import debounce from 'lodash-es/debounce';
```

**Follow-up Questions**:
- "Can you tree shake CSS?"
  - Answer: Not really. Use PurgeCSS/TailwindCSS instead
- "Does tree shaking work in development?"
  - Answer: No, only in production mode

---

#### Q6: What metrics do you use to measure React performance?

**Expected Answer**: "I track: LCP, FCP, TTI using Lighthouse. Component render times using React Profiler. Bundle sizes using webpack-bundle-analyzer. Runtime performance using Chrome DevTools. Real user metrics using web-vitals library."

**Core Web Vitals Priority**:

```
LCP (Largest Contentful Paint) - Load Speed ⭐ Most important
Goal: < 2.5 seconds
Measures: When largest element becomes visible

FID (First Input Delay) - Interactivity ⭐ Important
Goal: < 100 milliseconds
Measures: Time from click to browser response

CLS (Cumulative Layout Shift) - Stability ⭐ Important
Goal: < 0.1
Measures: Unexpected layout changes during load
```

**Other Important Metrics**:
- FCP (First Contentful Paint): < 1.8s
- TTI (Time to Interactive): < 3.8s
- TTFB (Time to First Byte): < 600ms
- TBT (Total Blocking Time): < 300ms

**Measurement Tools**:

```jsx
// 1. Lighthouse (Built-in Chrome DevTools)
Lighthouse → Generate Report
Best for: Quick audits, before/after comparison
Target Score: 90+

// 2. Web Vitals Library (Real User Metrics)
import { getLCP, getFID, getCLS } from 'web-vitals';
getLCP(metric => console.log('LCP:', metric.value));

// 3. React Profiler
const onRender = (id, phase, actualDuration) => {
  if (actualDuration > 1) console.log(`SLOW: ${id}`);
};
<Profiler id="App" onRender={onRender}>
```

**Real Example: Before & After**:

BEFORE OPTIMIZATION:
- LCP: 4.2s ✗ | FID: 250ms ⚠ | CLS: 0.35 ✗
- Lighthouse: 32 | Bundle: 850kb

AFTER OPTIMIZATION:
- LCP: 1.8s ✓ | FID: 85ms ✓ | CLS: 0.08 ✓
- Lighthouse: 94 | Bundle: 280kb (67% reduction)

**Follow-up Questions**:
- "Which metric is most important?"
  - Answer: LCP determines user perception of speed
- "How often should you measure?"
  - Answer: Continuous monitoring, manual audits monthly

---

#### Q7: How do you handle performance in a large team?

**Expected Answer**: "I implement: Performance budgets in CI/CD that fail builds if exceeded. Automated bundle size checks. Lighthouse CI audits. Performance guidelines documentation. Code review checklist. Shared optimized component library. Regular training."

**Team Performance Framework**:

```
1. INFRASTRUCTURE (Automated)
   ├─ Bundle Size Monitoring (fail if +50kb)
   ├─ Lighthouse CI (fail if < 80)
   └─ Performance Budget (LCP < 2.5s, FID < 100ms)

2. PROCESS (Standards)
   ├─ Code Review Checklist
   ├─ Performance Guidelines Document
   └─ Architectural Patterns

3. PEOPLE (Knowledge)
   ├─ Monthly Training Sessions
   ├─ Performance Ambassadors
   └─ Quarterly Performance Reviews

4. TOOLS (Shared)
   ├─ Pre-optimized Component Library
   ├─ Performance Dashboard
   └─ Performance Testing Setup
```

**Performance Guidelines**:

```markdown
# MUST DO
- ✓ Use named imports only
- ✓ Lazy load routes
- ✓ Memoize expensive components
- ✓ Add image dimensions (prevent CLS)
- ✓ Use React.memo on list items

# MUST NOT DO
- ✗ Default imports from large libraries
- ✗ Inline function definitions in JSX
- ✗ Create styled components inside render
- ✗ Use array index as React key
- ✗ Store large objects in Context without useMemo
```

**Follow-up Questions**:
- "How do you handle performance regression?"
  - Answer: Lighthouse CI fails the build automatically
- "What happens if team violates budget?"
  - Answer: Build fails, requires team discussion

---

#### Q8: Tell me about a performance issue you fixed. What was the root cause?

**How to Answer**: Show problem discovery, root cause analysis, solution, results, and learning.

**Example Strong Answer**:

"At my previous company, we had a dashboard showing 50+ charts. Initial load was taking 12 seconds.

**Problem Discovery**: Users complained. Lighthouse showed LCP of 8s.

**Root Cause Analysis**: 
- webpack-bundle-analyzer → All chart libraries bundled upfront (800kb)
- React Profiler → Charts rendered on mount even if not visible
- Network tab → Waiting for all chart data before rendering

**Solution Implemented**:
1. Code split chart component: `lazy(() => import('./Charts'))`
2. Lazy load charts based on active tab
3. Implement virtual scrolling with react-window
4. Add skeleton screens during load
5. Cache chart data with React Query (5-minute stale)

**Results**:
- LCP: 8s → 1.8s (77% improvement)
- Bundle: 850kb → 320kb (62% reduction)
- TTI: 12s → 3.5s (71% improvement)
- User satisfaction: 2.1/5 → 4.6/5

**Key Learning**: Performance optimization requires measuring at every step. Most developers optimize wrong things."

**What Interviewers Look For**:
- ✓ Used data-driven approach
- ✓ Used correct tools for diagnosis
- ✓ Applied multiple techniques
- ✓ Measured quantitatively
- ✓ Explained tradeoffs
- ✓ Learned from experience

---

#### Q9: When would you NOT optimize for performance?

**Expected Answer**:

"Interesting question. You shouldn't optimize if:

1. **Premature Optimization**
   - Don't optimize before measuring
   - Example: Adding React.memo everywhere
   - Cost exceeds benefit

2. **Optimization Cost > Benefit**
   - Takes 2 weeks but only saves 50ms
   - Code becomes unmaintainable
   - Users don't notice improvement

3. **Feature Not Yet Used**
   - Don't optimize unfinished features
   - Code might be deleted
   - Wait until stable and used

4. **Assumption Wrong**
   - Profile first - assumptions usually wrong
   - 90% of time in 10% of code

5. **User Base is Small**
   - 100 users on high-speed connections
   - Optimization ROI doesn't justify effort

**Key Principle**: Measure → Analyze → Decide → Implement → Verify

---

#### Q10: How do you approach performance testing in CI/CD?

**Expected Answer**: "I implement automated performance checks in the pipeline:

```javascript
// GitHub Actions Workflow
name: Performance Tests
on: [pull_request]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      # 1. Build
      - run: npm run build
      
      # 2. Check bundle size
      - run: |
          SIZE=$(du -sb dist | cut -f1)
          if [ $SIZE -gt 300000 ]; then exit 1; fi
      
      # 3. Run Lighthouse CI
      - uses: treosh/lighthouse-ci-action@v9
      
      # 4. Comment metrics on PR
      - uses: actions/github-script@v6
```

**Key Automated Checks**:
1. **Bundle Size** - Fail if +50kb
2. **Lighthouse Score** - Fail if < 80
3. **Core Web Vitals** - LCP < 2.5s, FID < 100ms
4. **Code Splitting** - Ensure chunks < 200kb
5. **Dependencies** - Warn if adding large deps

**If Performance Test Fails**:
- Build fails automatically
- Requires team discussion
- Options: Fix, increase budget (approval), revert

---

## Quick Reference: Interview Cheat Sheet

### When Asked "Tell me about your performance experience"
**Structure**: Problem → Measurement → Solution → Results → Learning

### When Asked "How do you optimize X"
**Process**: Profile → Analyze → Implement ONE change → Measure → Repeat

### When Asked "What's your performance toolkit"
**Tools**: Lighthouse, React Profiler, webpack-bundle-analyzer, web-vitals
**Libraries**: React Query, React.memo, useMemo, useCallback
**Techniques**: Code splitting, lazy loading, memoization, caching

### Red Flags (AVOID SAYING)
- ✗ "I optimize without measuring"
- ✗ "We use React.memo everywhere"
- ✗ "Performance doesn't matter much"
- ✗ "I don't know what our metrics are"

### Green Flags (ALWAYS SAY)
- ✓ "We measure first, optimize based on data"
- ✓ "We have performance budgets in CI/CD"
- ✓ "We track real user metrics with web-vitals"
- ✓ "We trade off code complexity vs benefit"
- ✓ "Performance is part of our culture"

---

## Advanced Techniques

### 1. Web Workers for Heavy Computation

```jsx
// worker.js
self.onmessage = function(e) {
  const result = heavyComputation(e.data);
  self.postMessage(result);
};

function heavyComputation(data) {
  // CPU-intensive work
  return processedData;
}

// Component using worker
const HeavyComputationComponent = ({ data }) => {
  const [result, setResult] = useState(null);
  const workerRef = useRef(null);

  useEffect(() => {
    workerRef.current = new Worker('/worker.js');

    workerRef.current.onmessage = (e) => {
      setResult(e.data);
    };

    return () => {
      workerRef.current?.terminate();
    };
  }, []);

  useEffect(() => {
    if (workerRef.current && data) {
      workerRef.current.postMessage(data);
    }
  }, [data]);

  return <div>{result ? <DisplayResult data={result} /> : 'Computing...'}</div>;
};
```

### 2. Intersection Observer for Lazy Components

```jsx
const useLazyLoad = (ref, options = {}) => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      options
    );

    if (ref.current) {
      observer.observe(ref.current);
    }

    return () => observer.disconnect();
  }, [ref, options]);

  return isVisible;
};

const LazySection = ({ children }) => {
  const ref = useRef();
  const isVisible = useLazyLoad(ref, { threshold: 0.1 });

  return (
    <div ref={ref}>
      {isVisible ? children : <div style={{ height: '400px' }}>Loading...</div>}
    </div>
  );
};
```

### 3. Request Deduplication

```jsx
const requestCache = new Map();

const deduplicatedFetch = async (url, options = {}) => {
  const key = `${url}-${JSON.stringify(options)}`;

  if (requestCache.has(key)) {
    return requestCache.get(key);
  }

  const request = fetch(url, options)
    .then(res => res.json())
    .finally(() => {
      // Clear cache after response
      setTimeout(() => requestCache.delete(key), 1000);
    });

  requestCache.set(key, request);
  return request;
};

// Hook using deduplicated fetch
const useDeduplicatedAPI = (url) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    deduplicatedFetch(url)
      .then(setData)
      .finally(() => setLoading(false));
  }, [url]);

  return { data, loading };
};
```

This comprehensive guide covers all major aspects of React performance optimization, code splitting, lazy loading, caching, and bundle optimization with practical examples and interview-ready explanations.