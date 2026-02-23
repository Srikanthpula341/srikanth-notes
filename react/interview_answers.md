# Java — Core Interview Answers (Q1–50)

This document contains senior-level answers to common Core Java interview questions (questions 1–50). Each answer is concise but thorough, focusing on practical considerations, trade-offs, and where the topics matter in real systems.

## Table of Contents

1. What are the main OOP principles?
2. Difference between abstraction and encapsulation?
3. What is polymorphism with examples?
4. Method overloading vs overriding?
5. What is immutability?
6. How does HashMap work internally?
7. What happens when hash collisions occur?
8. ConcurrentHashMap vs HashMap?
9. Difference between ArrayList and LinkedList?
10. Comparable vs Comparator?
11. What is equals() and hashCode() contract?
12. How does Java memory management work?
13. Stack vs Heap memory?
14. What is garbage collection?
15. Types of garbage collectors?
16. What is JVM?
17. JDK vs JRE vs JVM?
18. What is classloader?
19. String pool concept?
20. Why String is immutable?
21. What is reflection?
22. What is serialization?
23. transient keyword?
24. volatile keyword?
25. synchronized keyword?
26. What is thread safety?
27. Runnable vs Callable?
28. Executor framework?
29. Future vs CompletableFuture?
30. Deadlock and prevention?
31. wait() vs sleep()?
32. notify vs notifyAll?
33. Atomic variables?
34. Functional interfaces?
35. Lambda expressions?
36. Streams API?
37. Intermediate vs terminal operations?
38. Optional class?
39. Generics?
40. Type erasure?
41. Exception hierarchy?
42. Checked vs unchecked exceptions?
43. try-with-resources?
44. Marker interfaces?
45. Annotations?
46. Design patterns in Java?
47. Singleton implementation?
48. Builder pattern?
49. Factory pattern?
50. Dependency injection concept?

---

### 1. What are the main OOP principles?

The four core OOP principles are Encapsulation (bundling state and behavior; controlling access via visibility and APIs), Abstraction (exposing essential behavior while hiding complexity), Inheritance (reusing and extending behavior via parent-child relationships), and Polymorphism (objects presenting different implementations through a common interface). At senior level, emphasize designing for composition over inheritance, using interfaces to define contracts, and leveraging encapsulation to maintain invariants and evolve internals without breaking clients.

### 2. Difference between abstraction and encapsulation?

Abstraction is about modeling — exposing what an object does (its public contract) while hiding internal complexity. Encapsulation is about protection — bundling data with methods and restricting direct access (private fields, controlled setters). Practically, abstraction drives API design and encapsulation enforces invariants and prevents misuse. Both are used together: an abstract interface defines the contract and encapsulation hides the concrete implementation.

### 3. What is polymorphism with examples?

Polymorphism lets code operate on objects through a common type while concrete behavior varies at runtime. Examples: subtype polymorphism (interface List with ArrayList/LinkedList implementations), overridden methods (a Service interface with different implementations selected via DI), and parametric polymorphism via generics (List<T>). At runtime, virtual dispatch selects the correct override; at design time, polymorphism enables loose coupling and easier testing.

### 4. Method overloading vs overriding?

Overloading is compile-time: same method name but different parameter lists in the same class (or subclass). Overriding is runtime polymorphism: a subclass provides a different implementation for a method declared in a superclass or interface (same signature). Overriding affects behavior via dynamic dispatch; overloading is syntactic convenience resolved at compile time.

### 5. What is immutability?

An immutable object cannot change state after construction. Immutability simplifies reasoning about concurrency, caching, and equality. Implement via final fields, no mutators, defensive copying, and careful handling of mutable internals. Use immutable value objects (String, BigInteger) for safety; prefer immutable APIs when possible and document construction costs for large objects.

### 6. How does HashMap work internally?

A HashMap stores entries in an array of buckets; keys are hashed and mapped to a bucket index. Within each bucket entries are chained (historically linked lists, converted to balanced trees for long chains in modern JDKs). On get/put, HashMap computes hash, finds the bucket, and either searches linearly (list) or via tree lookup. It resizes (rehashes) when load factor threshold reached, which is an O(n) operation intermittently. Pay attention to proper hashCode implementations and initial capacity to avoid resizing and collisions in high-throughput systems.

### 7. What happens when hash collisions occur?

Collisions map multiple keys to the same bucket. HashMap stores colliding entries in a chain; for small chains it uses a linked list and switches to a balanced tree (TreeNode/Red-Black) when chain length surpasses a threshold. Collisions increase lookup time and can be exploited by attackers, so use well-distributed hash functions and consider limiting exposure in web APIs (e.g., use concurrent data structures or defend against untrusted-key DOS).

### 8. ConcurrentHashMap vs HashMap?

HashMap is not thread-safe; concurrent access can corrupt internal structures. ConcurrentHashMap is designed for concurrency: earlier versions partitioned buckets into segments, modern implementations use lock-striping and CAS for finer-grained concurrency without locking the whole map. ConcurrentHashMap provides eventual consistency for size(), no locking for reads, and weakly consistent iterators. Use ConcurrentHashMap for high-concurrency caches and maps; use Collections.synchronizedMap only for simpler, coarser synchronization needs.

### 9. Difference between ArrayList and LinkedList?

ArrayList is an array-backed list offering O(1) random access and amortized O(1) append; removals/inserts away from tail are O(n) due to shifting. LinkedList is a doubly-linked list offering O(1) insert/remove with a known node reference but O(n) random access. For most use-cases ArrayList is preferred because of better locality and lower overhead; use LinkedList only when you have many insertions/removals at known positions and heavy iterator-based manipulations.

### 10. Comparable vs Comparator?

Comparable defines a natural ordering on objects via a compareTo method (class-level). Comparator is a strategy object that defines an external ordering and can be supplied when sorting or ordering is needed. Prefer Comparator for multiple orderings and to avoid coupling model classes to a single sort order. Use static factory methods like Comparator.comparing for concise, null-safe comparators.

### 11. What is equals() and hashCode() contract?

The contract: if two objects are equal according to equals(), they must have the same hashCode(). hashCode() does not need to be unique, but must be consistent across invocations while the object state used in equals/hashCode remains unchanged. Violating the contract breaks hash-based collections. Implement both together, prefer final fields for equality, and consider using IDE-generated or library helpers (Objects.equals/hash) to avoid subtle bugs.

### 12. How does Java memory management work?

Java memory is managed by the JVM: code and data live in regions like the heap (objects), stack (frames/local primitives), metaspace (class metadata), and native memory. The GC reclaims unreachable objects on the heap. Developers control object lifetime indirectly by dropping references, tuning GC, and using appropriate data structures. Heap sizing, young/old generation ratios, and GC algorithm choice are key levers for performance and latency.

### 13. Stack vs Heap memory?

Stack holds method frames, local variables, and reference values — it's thread-local and short-lived. Heap stores objects and arrays, shared across threads, and managed by GC. Stack allocation is fast and deterministic; heap allocation is cheaper than freeing thanks to GC but can incur pauses for collection. Avoid large objects on the stack (not possible) and be mindful of reference lifetimes to prevent memory leaks.

### 14. What is garbage collection?

Garbage collection is the automated process in the JVM that reclaims memory occupied by objects that are no longer reachable from GC roots. GC algorithms identify live objects via root tracing and reclaim unreachable memory, optionally compacting the heap. GC relieves developers from manual memory management but requires tuning for performance-sensitive systems to control pause times and throughput.

### 15. Types of garbage collectors?

Common JVM collectors: Serial (single-threaded, simple), Parallel (throughput-oriented), CMS (concurrent low-pause, older), G1 (regional, balanced latency/throughput), ZGC and Shenandoah (low-pause collectors using concurrent compaction). Choose based on latency requirements: G1/ZGC for low-latency large heaps; Parallel for batch throughput; tune generations, GC threads, and ergonomics accordingly.

### 16. What is JVM?

JVM (Java Virtual Machine) is the runtime that loads bytecode, verifies it, JIT-compiles hotspots to native code, manages memory and threads, and provides platform abstraction. It includes subsystems: class loader, garbage collector, JIT compiler, and runtime services. Understanding JVM behavior (JIT, GC, memory layout) is vital for diagnosing performance issues in production.

### 17. JDK vs JRE vs JVM?

JVM is the runtime engine. JRE (Java Runtime Environment) bundles the JVM and standard libraries required to run Java programs. JDK (Java Development Kit) includes the JRE plus development tools (javac, jar, jdb). For production, run on a JRE/JDK distribution tailored to your CI/CD and runtime needs; many deployments use a trimmed JRE or container images with only required modules.

### 18. What is classloader?

A classloader loads classes and resources into the JVM, converting binary class data into Class objects. Java uses a delegation model (bootstrap, extension/platform, application) to avoid multiple copies and ensure core classes are loaded by trusted loaders. Custom classloaders support plugin systems, hot reloading, and isolation; they must handle security, resource lookup, and parent delegation carefully to avoid leaks and conflicts.

### 19. String pool concept?

The String pool (intern pool) stores unique string literals to save memory and allow fast equality checks by reference. String literals and interned strings share instances; calling intern() adds a string to the pool. Use it for many repeated literals, but beware of large pools causing memory pressure. Since strings are immutable, pooling is safe; prefer intern for a controlled set of frequently used, repeated values.

### 20. Why String is immutable?

Strings are immutable to enable safe sharing, caching (hashCode), and use as keys in collections. Immutability prevents accidental modification across consumers and simplifies concurrency (no synchronization required). It also enables optimizations like string pooling and secure APIs (e.g., passing strings to sensitive methods without copying). For mutable text, use StringBuilder or StringBuffer (thread-safe but slower).

### 21. What is reflection?

Reflection is the runtime inspection and manipulation of classes, methods, fields, and annotations. It enables frameworks, DI containers, and serializers to operate without compile-time coupling. Reflection is powerful but costly (performance), bypasses encapsulation (can break invariants), and interacts with security managers; use it judiciously and cache reflective lookups for performance.

### 22. What is serialization?

Serialization converts an object graph to a byte-stream for persistence or transmission; deserialization reconstructs it. Java's built-in serialization (Serializable) is flexible but fragile and risky (security, versioning). Prefer explicit, versioned formats (JSON, protobuf) or custom serialization mechanisms with schema evolution and clear compatibility guarantees for production systems.

### 23. transient keyword?

`transient` marks fields to be skipped during Java serialization. Use for derived state, non-serializable handles, or security-sensitive data (passwords). When deserialized, transient fields get default values; implement readObject/writeObject or use custom serializers if you need controlled restoration.

### 24. volatile keyword?

`volatile` ensures visibility of writes to other threads and prohibits certain reordering; reads/writes to volatile variables have memory visibility guarantees but are not atomic for compound operations. Use volatile for flags or single-writer/multiple-reader patterns; for atomic increments or compound state, prefer Atomic* classes or locks.

### 25. synchronized keyword?

`synchronized` provides mutual exclusion and establishes a happens-before relationship for visibility. It can be applied to methods or blocks. Modern JVMs optimize uncontended synchronized paths, but locks still have overhead and can cause contention; prefer higher-level concurrency primitives (Lock, ReadWriteLock, concurrent collections) when appropriate.

### 26. What is thread safety?

Thread safety means correct behavior when accessed concurrently. Strategies include immutability, confinement (thread-local), synchronization, lock-free algorithms (Atomics), and using concurrent collections. At senior level, design for minimal locking regions, prefer well-tested concurrency primitives, and reason about liveness (deadlocks) and fairness when choosing synchronization approaches.

### 27. Runnable vs Callable?

Runnable represents a task with no return value and cannot throw checked exceptions. Callable returns a result and can throw checked exceptions. Use Callable when you need a result or exception propagation; submit Callables to ExecutorService to obtain Futures for results and cancellation control.

### 28. Executor framework?

The Executor framework decouples task submission from execution. ExecutorService, ThreadPoolExecutor, and ScheduledThreadPoolExecutor provide thread pooling, queuing, rejection policies, and lifecycle management. Tune pool sizes, queue types (bounded vs unbounded), and rejection handlers based on workload characteristics (IO-bound vs CPU-bound) and implement graceful shutdown for production systems.

### 29. Future vs CompletableFuture?

Future represents a pending result with blocking get(); it has limited composition. CompletableFuture provides non-blocking composition, async callbacks, combinators (thenApply, thenCombine), and explicit completion. Use CompletableFuture for reactive-style, asynchronous flows and to build complex pipelines without blocking threads.

### 30. Deadlock and prevention?

Deadlock occurs when threads wait cyclically for locks. Prevent using strategies: acquire locks in a consistent global order, use tryLock with timeouts, minimize lock scope, prefer lock ordering or lock coupling, and detect via monitoring (thread dumps). Design systems to avoid long-held locks and prefer non-blocking algorithms when low latency is critical.

### 31. wait() vs sleep()?

`sleep()` pauses the current thread for a duration without releasing locks. `wait()` (Object.wait) releases the monitor and suspends until notified; it's used for inter-thread coordination with notify/notifyAll and requires owning the object's monitor. Use wait/notify for condition-based waits and sleep for timed pauses unrelated to lock semantics.

### 32. notify vs notifyAll?

`notify()` wakes a single waiting thread; `notifyAll()` wakes all waiting threads on the monitor. Use notifyAll() when multiple conditions exist or to avoid lost wakeups and subtle bugs; notify() can be more efficient but can cause missed signals if used incorrectly. Prefer higher-level concurrency constructs (Condition, BlockingQueue) for clearer semantics.

### 33. Atomic variables?

Atomic classes (AtomicInteger, AtomicReference, etc.) provide lock-free, CAS-based operations for atomic updates and are useful for counters, flags, and simple state management. They reduce contention and provide better scalability than locks for certain patterns, but for complex invariants use locks or transactional approaches. Beware of ABA problems for CAS on raw references; AtomicStampedReference can help.

### 34. Functional interfaces?

A functional interface has a single abstract method and can be instantiated with a lambda or method reference (e.g., Runnable, Function<T,R>). They enable concise behavior passing and are central to streams and modern API design. Use @FunctionalInterface for clarity and to maintain compatibility during evolution.

### 35. Lambda expressions?

Lambdas are lightweight function literals that implement functional interfaces; they improve readability and reduce boilerplate. Under the hood, the JVM may generate invokedynamic call sites or synthetic classes; capturing lambdas may allocate objects. Use them for concise callbacks, functional composition, and stream pipelines.

### 36. Streams API?

Streams provide a declarative pipeline for transforming and processing collections (map/filter/reduce). Streams separate data source from computation, support lazy evaluation, and parallel execution via parallelStream. For large-scale systems, measure overhead vs manual loops, avoid shared mutable state in parallel streams, and prefer collections optimized for parallel processing.

### 37. Intermediate vs terminal operations?

Intermediate operations (map, filter) are lazy and return another stream; they build the pipeline. Terminal operations (collect, forEach, reduce) trigger evaluation and produce results. This lazy evaluation enables optimization like short-circuiting and fusion; design pipelines to minimize work and avoid side effects.

### 38. Optional class?

Optional is a container that may hold a non-null value, used to avoid nulls and convey optionality in APIs. Use Optional for return values (not for fields/parameters typically) and prefer map/flatMap/orElse patterns over direct isPresent checks. Avoid overuse that complicates callers; it's an API-level tool for clearer contracts.

### 39. Generics?

Generics provide compile-time type safety and reusability (List<String>). They enable a single implementation to work across types. At runtime, type information is erased (type erasure), so operations that depend on runtime types require care (casts, instanceof with generics). Use bounded wildcards (<? extends T>, <? super T>) to express variance in APIs.

### 40. Type erasure?

Type erasure removes generic type parameters at runtime, replacing them with their bounds (usually Object). This maintains backward compatibility but limits runtime type checks and prevents creating generic arrays. Workarounds include passing Class<T> tokens, using explicit converters, or designing APIs that avoid needing runtime generic type information.

### 41. Exception hierarchy?

Java exceptions derive from Throwable, split into Exception (checked) and Error (serious JVM problems). RuntimeException and its subclasses are unchecked errors caused by programmer mistakes. Design APIs to throw meaningful exceptions, favor unchecked exceptions for programming errors, and use checked exceptions when the caller can reasonably recover.

### 42. Checked vs unchecked exceptions?

Checked exceptions are part of method signatures and force the caller to handle or declare them; unchecked exceptions (RuntimeException) do not. Use checked exceptions for recoverable, expected failure modes (I/O issues) and unchecked for unrecoverable programming errors (NullPointerException). Overusing checked exceptions can clutter APIs; balance clarity and ergonomics.

### 43. try-with-resources?

Try-with-resources ensures deterministic closing of AutoCloseable resources and simplifies exception handling by suppressing secondary exceptions properly. Prefer it for I/O, JDBC, and similar resources to avoid leaks. For complex cleanup, consider explicit resource managers when lifecycle is non-local.

### 44. Marker interfaces?

Marker interfaces (Serializable, Cloneable) convey metadata without methods. They signal special treatment by frameworks or the runtime. Prefer annotations or explicit interfaces with behavior for clearer intent; marker interfaces are legacy in many cases but still used by core APIs.

### 45. Annotations?

Annotations provide metadata for code (runtime or compile-time) used by frameworks, tools, and the compiler. Use them to declare behavior (DI, validation, mapping). Design custom annotations with retention and target policies, keep them small, and document semantics for tooling and backward compatibility.

### 46. Design patterns in Java?

Common patterns: Singleton, Factory, Builder, Strategy, Observer, Decorator, Adapter, Repository, and Dependency Injection. Use patterns as communication tools; avoid overusing them — prefer simple, composable designs. At senior level, select patterns that improve testability, modularity, and explicit responsibilities.

### 47. Singleton implementation?

Preferred implementation is the enum-based singleton (Joshua Bloch): it’s simple, provides serialization guarantee, and resists reflection-based attacks. Alternatives include private constructor + static factory with final instance or lazy holder idiom. Understand when singletons introduce global state and consider dependency injection for better testability.

### 48. Builder pattern?

Builder separates complex object construction from representation, improving readability and immutability for objects with many optional parameters. Use static nested Builder classes or libraries (AutoValue, Lombok) to reduce boilerplate. Builders improve API stability and are especially useful for domain objects and configuration components.

### 49. Factory pattern?

Factory encapsulates object creation, decoupling clients from concrete implementations. Use simple factories or abstract factories for families of related objects. Combine with DI to wire concrete types; factories are useful when creation involves logic, caching, or type selection.

### 50. Dependency injection concept?

Dependency Injection (DI) inverts control of creating dependencies — objects receive collaborators from an external injector (constructor, setter, field). DI improves modularity, testability, and configuration flexibility. Use constructor injection for mandatory dependencies, prefer explicit wiring via frameworks (Spring, Guice) or lightweight factories, and avoid service locators that hide dependencies.
