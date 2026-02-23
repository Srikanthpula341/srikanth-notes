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

## Section 2 — Spring Boot / Backend (Q51–Q75)

### 51. What is Spring Boot?

Spring Boot is an opinionated framework built on Spring that accelerates application development by providing auto-configuration, sensible defaults, and embedded runtime components (Tomcat/Jetty/Netty). It removes boilerplate configuration required to bootstrap a Spring application, offering starters (pom dependencies) that aggregate commonly used libraries and auto-configure beans based on classpath contents and properties. For production-grade systems, Spring Boot streamlines common operational concerns: externalized configuration via `application.properties`/`application.yml`, health checks through Actuator, metrics integration, and easy packaging into executable JARs/containers.

At a senior level, emphasize Spring Boot's value in reducing plumbing and enforcing conventions while also noting pitfalls: auto-configuration can hide complexity and couple behavior to classpath composition, so explicit configuration and understanding the auto-configured beans are essential for predictable behavior. Use `spring.factories`/`@EnableAutoConfiguration` patterns when building custom starters and prefer configuration properties classes for type-safe config binding.

### 52. How does Spring Boot work internally?

Spring Boot coordinates a startup sequence that discovers and registers auto-configuration classes, loads application properties, and initializes an ApplicationContext. Key steps: the `SpringApplication` class sets up the environment, reads `application.properties`/`yaml`, selects an `ApplicationContext` implementation (e.g., `AnnotationConfigApplicationContext` for standard apps or `SpringApplication.run` which creates a `SpringApplication`), and triggers auto-configuration via `@EnableAutoConfiguration` which is driven by `spring.factories`. Auto-configuration classes are conditional (via `@ConditionalOnMissingBean`, `@ConditionalOnClass`, etc.), meaning they only create beans when their conditions match the runtime environment.

Internally, Spring Boot registers `BeanFactoryPostProcessor` and `BeanPostProcessor` implementations that manipulate bean definitions and instances before and after initialization. The embedded server (Tomcat/Jetty/Netty) is auto-configured and started as part of context refresh. Actuator endpoints and metrics are registered via conditional configuration. For production, inspect the auto-configurations (`/config`) and use `spring.main.banner-mode=off`, `management.endpoints.web.exposure.include`, and `debug=true` to diagnose what Boot auto-configured.

### 53. What is dependency injection?

Dependency Injection (DI) is a design pattern where an external component (the container or injector) provides an object's dependencies rather than the object creating them. The goal is to invert control of dependency creation and wiring, enabling loose coupling, easier testing (by injecting mocks), and centralized configuration. DI can be achieved via constructor injection (preferred for required dependencies), setter injection (for optional/late-bound dependencies), or field injection (less preferred due to reduced testability and hidden dependencies).

In Spring, DI is implemented by the IoC container: annotated components (`@Component`, `@Service`, `@Repository`, `@Controller`) or explicit `@Bean` methods are discovered and registered; the container resolves dependencies by type (and optionally by qualifier or name) and injects them at creation time. For complex setups use `@Configuration` classes with factory methods, explicit `@Qualifier` and `@Primary` rules, and prefer constructor injection for immutability and simpler unit testing. At scale, DI reduces boilerplate, but be mindful of overly broad component scanning and cyclic dependencies which indicate design smells.

### 54. Bean lifecycle?

A Spring bean undergoes a well-defined lifecycle managed by the ApplicationContext. Lifecycle stages: instantiation (constructor or factory method), dependency injection (setting properties or constructor args), `BeanPostProcessor` pre-initialization callbacks, `@PostConstruct` (or custom `init-method`), initialization callbacks and `BeanPostProcessor` post-initialization, usage, and finally destruction (`@PreDestroy` or `destroy-method`) when the context shuts down. For prototype-scoped beans the container performs instantiation and dependency injection but does not manage the full lifecycle or destruction.

At senior level, understand extension points: `BeanFactoryPostProcessor` modifies bean definitions before bean creation; `BeanPostProcessor` intercepts instances before/after initialization (used by AOP proxies, proxy creation, and @Autowired processing). Use `SmartInitializingSingleton` for logic to run after all singletons are initialized, and `DisposableBean`/`InitializingBean` for lifecycle hooks when necessary. Keep lifecycle callbacks minimal — favor explicit initialization via factory methods for testability.

### 55. @Component vs @Service vs @Repository?

All three are stereotypes and functionally similar (they mark classes as candidates for component scanning). `@Component` is a generic stereotype. `@Service` indicates service-layer semantics (business logic), and `@Repository` signals persistence-layer components and has special translation semantics: Spring wraps `@Repository`-annotated classes to translate persistence exceptions into Spring's `DataAccessException` hierarchy. Use `@Repository` for DAOs, `@Service` for business services, and `@Component` for lower-level or cross-cutting components.

From a design perspective, using specific stereotypes improves readability and enables framework behavior (exception translation), while facilitating systematic component scanning and clearer package organization.

### 56. @Autowired vs constructor injection?

`@Autowired` is Spring's annotation for dependency injection. It can be applied to fields, setters, or constructors. Constructor injection (either via `@Autowired` on a constructor or simply a single constructor without `@Autowired` in recent Spring versions) is the recommended approach: it makes dependencies explicit, works well with immutability, and simplifies unit testing. Field injection hides dependencies and complicates testing and object creation outside the container.

Constructor injection also prevents partially-initialized objects and eliminates the possibility of circular dependencies at runtime (forcing you to address them during design). Use `@Autowired(required=false)` or `Optional<T>` for optional dependencies, but prefer explicit configuration and fallback beans for clarity.

### 57. @Configuration vs @Bean?

`@Configuration` marks a class as a source of bean definitions; methods annotated with `@Bean` inside a `@Configuration` class declare bean factory methods. `@Configuration` classes are enhanced (CGLIB proxies) so that `@Bean` methods are singletons by default and calls between `@Bean` methods go through the container to ensure shared instances. Using `@Component` plus `@Bean` in non-`@Configuration` classes (or `@Configuration(proxyBeanMethods=false)`) changes semantics and avoids proxying when you don't need inter-bean references.

Prefer `@Configuration` for explicit wiring, reuse, and when you require container-managed singleton behavior. For lightweight factory methods prefer `@Component` with `@Bean` or `@Import` as appropriate.

### 58. What is IoC container?

The Inversion of Control (IoC) container is the core of the Spring framework that manages bean creation, wiring, lifecycle, and configuration. It reads bean definitions (annotations, XML, `@Bean` methods), resolves dependencies, applies post-processors, and provides the ApplicationContext for retrieving beans and resources. The container decouples object creation from use, enabling features like AOP, transaction management, and scoped proxies. For large applications, understand the container's memory footprint and startup cost; use lazy initialization, profile-based beans, and conditional beans to reduce resource usage.

### 59. What is Spring MVC?

Spring MVC is a request-driven web framework built on the DispatcherServlet front controller pattern. It maps HTTP requests to controller handler methods (annotated with `@Controller`/`@RequestMapping`), converts request data to method arguments via `HandlerMethodArgumentResolver`s, performs validation, and resolves views via `ViewResolver`s (Thymeleaf, JSP) or returns data for REST controllers (`@ResponseBody`/`@RestController`). Spring MVC is highly configurable with interceptors, filters, message converters (JSON/XML), and content negotiation.

Design considerations: separate web concerns (controllers) from services, use DTOs for request/response shapes, validate at the boundary, and keep controllers thin. For high-throughput APIs, prefer lightweight serialization configuration and tune connection/thread pools at the servlet container level.

### 60. DispatcherServlet flow?

`DispatcherServlet` is the central servlet that receives incoming HTTP requests and dispatches them to registered handlers. Flow: request arrives → `DispatcherServlet` receives it → determines `HandlerMapping` to find a handler (controller) → obtains a `HandlerAdapter` to invoke the handler method → handler executes business logic → returns a `ModelAndView` or response body → `ViewResolver` renders a view (or `HttpMessageConverter` writes body) → response returned. Along the way, `HandlerInterceptors` can pre/post-process requests, and exceptions are handled via `HandlerExceptionResolver` or `@ControllerAdvice`.

Internally, HandlerMapping implementations (e.g., `RequestMappingHandlerMapping`) inspect controller annotations; the adapter (`RequestMappingHandlerAdapter`) handles argument resolution, data binding, validation, and return value handling. For production, tune servlet thread pools and avoid blocking operations in controller threads.

### 61. @RestController vs @Controller?

`@Controller` marks a class as an MVC controller and typically returns views; methods annotated with `@ResponseBody` return raw responses. `@RestController` is a convenience annotation that combines `@Controller` and `@ResponseBody`, making methods return serialized objects (usually JSON) directly. Use `@RestController` for REST APIs and `@Controller` when serving server-side rendered views. Keep controllers focused on request handling and delegate business logic to service layers.

### 62. Request lifecycle in Spring?

A typical request lifecycle: incoming HTTP request → servlet container hands to `DispatcherServlet` → preHandle interceptors → handler mapping → controller invocation (argument resolution, validation) → service layer processing → controller return (ModelAndView or body) → view resolution or message conversion → postHandle interceptors → `DispatcherServlet` completes and triggers after-completion interceptors. Throughout this lifecycle, exception resolvers and filters may intervene. For tracing and observability, integrate interceptors or filters to capture correlation IDs and timing metrics.

### 63. Filters vs Interceptors?

Filters (Servlet API) operate at the container level and can modify request/response streams, apply to any servlet-based component, and run before Spring MVC is initialized. Interceptors (`HandlerInterceptor`) are Spring MVC-specific and work at the handler invocation level, providing preHandle/postHandle/afterCompletion hooks with access to handler metadata. Use filters for cross-cutting concerns that require access to raw request/response (e.g., request wrapping, security at the servlet layer), and interceptors for handler-level concerns like authorization checks, request metrics, or adding model attributes.

### 64. HandlerInterceptor usage?

`HandlerInterceptor` provides preHandle/postHandle/afterCompletion hooks around controller execution. Use it for authentication/authorization checks, request-scoped logging, measuring execution time, and adding common model attributes for views. Because interceptors have access to handler metadata and resolved handler methods, they are ideal for cross-cutting web concerns that depend on controller context. For async requests, be mindful of thread context and clean up in `afterCompletion`.

### 65. Exception handling in Spring?

Spring offers multiple strategies: controller-level `@ExceptionHandler` methods, global `@ControllerAdvice` classes for cross-cutting exception handling, and `HandlerExceptionResolver` implementations. For REST APIs, map exceptions to meaningful HTTP status codes and standard error payloads. Capture and log stack traces centrally with correlation IDs, and avoid leaking internal implementation details in responses. Prefer explicit exception hierarchies (e.g., `EntityNotFoundException`, `ValidationException`) and map them consistently to clients.

### 66. @ControllerAdvice?

`@ControllerAdvice` is a specialized component for global exception handling, model attribute population, and binding configuration across controllers. It centralizes `@ExceptionHandler`, `@InitBinder`, and `@ModelAttribute` methods so you can return consistent error responses and apply cross-cutting request handling. Use it to enforce API error formats, default validation messages, and to attach global attributes like user info when rendering views.

### 67. @Transactional working?

`@Transactional` demarcates transactional boundaries. Spring implements it via proxies (AOP) that start a transaction before method execution and commit or rollback afterward based on exceptions and propagation rules. Transactions are managed by a `PlatformTransactionManager` (e.g., `DataSourceTransactionManager`, `JpaTransactionManager`) which interacts with JDBC connections or JPA `EntityManager`s. Transactions control isolation, rollback rules, and timeout behavior.

Key considerations: `@Transactional` is only effective on public methods invoked through the proxy; self-invocation bypasses the proxy and won't start a transaction. For read-only operations, set `readOnly=true` to hint optimizations. Keep transactional boundaries coarse enough to maintain consistency but small enough to reduce lock contention.

### 68. Propagation types?

Propagation controls how transactional contexts are handled when a transactional method calls another transactional method. Common types: `REQUIRED` (join existing transaction or create new), `REQUIRES_NEW` (suspend existing and create new transaction), `SUPPORTS` (execute within existing or non-transactional if none), `MANDATORY` (must have existing transaction), `NOT_SUPPORTED` (suspend existing and execute non-transactionally), `NEVER` (throw if transaction exists), and `NESTED` (create a nested savepoint-based transaction when supported). Choose propagation based on isolation needs, compensating actions, and failure semantics — `REQUIRES_NEW` is useful for independent work (audit logs) that must persist even if caller rolls back.

### 69. Isolation levels?

SQL isolation levels define visibility of transactional changes and control phenomena like dirty reads, non-repeatable reads, and phantom reads. Common levels: `READ_UNCOMMITTED`, `READ_COMMITTED`, `REPEATABLE_READ`, `SERIALIZABLE`. Each level trades off concurrency and consistency; databases implement them differently (e.g., Oracle's `READ_COMMITTED` vs PostgreSQL's MVCC). In Spring set isolation on `@Transactional` when you need stronger guarantees; otherwise rely on default DB isolation and design for eventual consistency where appropriate.

### 70. Lazy vs eager loading?

Lazy loading defers fetching related entities until accessed; eager loading fetches associations immediately. Lazy reduces initial query cost but can cause N+1 query problems when iterating collections, while eager loading can result in over-fetching and large payloads. Use DTO projections, fetch joins, or batch fetching to balance performance. For REST APIs, avoid returning lazy entities directly — map to DTOs and control fetch semantics in queries.

### 71. Hibernate session lifecycle?

The Hibernate `Session` (or JPA `EntityManager`) represents a unit of work and maintains a first-level cache of managed entities. Typical lifecycle: open session/EM → begin transaction → perform CRUD/load operations (entities become managed) → flush (synchronize state with DB) → commit/rollback → close session. In Spring, sessions are usually bound to a transaction and managed by `JpaTransactionManager`. Be mindful of session-per-request patterns, lazy loading outside session scope (LazyInitializationException), and long sessions causing memory growth. Use explicit DTO queries or fetch strategies to control loading.

### 72. JPA vs Hibernate?

JPA is a specification (API) for ORM in Java; Hibernate is a mature implementation of JPA with additional features beyond the spec (Criteria API extensions, better caching, tooling). Design to the JPA API for portability, but leverage Hibernate-specific optimizations (second-level cache, stateless sessions, multi-tenancy) when needed. Using provider-specific features couples you to the implementation but can yield significant performance or operational benefits.

### 73. Entity states?

JPA entity states: transient (new, not associated with a persistence context), managed/persistent (attached to a session), detached (previously managed but no longer attached), and removed (scheduled for deletion). Transitions occur via `persist`, `merge`, `remove`, and on transaction commit. Understanding these states is essential for correct merging semantics, avoiding unintended updates, and managing identity and equality semantics.

### 74. N+1 problem?

The N+1 problem occurs when an initial query loads N parent entities and then issues additional queries per entity to load child associations, resulting in N+1 queries and poor performance. Prevent it with fetch joins (`JOIN FETCH`), batch fetching, entity graphs, or DTO projection queries that retrieve required data in a single optimized query. Monitor SQL in production and use profiling to detect N+1 patterns; fix at the query layer rather than by increasing hardware.

### 75. Fetch types?

Fetch types (LAZY, EAGER) control when associations are loaded. `LAZY` defers loading until accessed; `EAGER` loads associations immediately with the owning entity. Defaults differ (e.g., `@ManyToOne` often defaults to EAGER historically, but best practice is to prefer `LAZY` and fetch explicitly). Use DTO projections, fetch joins, and query tuning to control the actual SQL executed and avoid unexpected data loading and serialization issues.

## Section 2B — Spring Boot / Backend (Q76–Q100)

### 76. Pagination in Spring?

Pagination in Spring is typically handled via the Spring Data abstractions: `Pageable` and `Page<T>`. Repositories extending `PagingAndSortingRepository` or `JpaRepository` accept a `Pageable` parameter and return a `Page` object that includes content, total elements, total pages, and paging metadata. For APIs, expose page number and size parameters (or use cursor-based tokens for high-scale systems) and validate input to prevent expensive queries. Use `Slice<T>` for streamed access when you only need the next page without total counts — it avoids the extra `COUNT` query which can be costly on large tables.

From a senior perspective, design pagination for the workload: OFFSET-based pagination is simple but suffers from poor performance on deep pages; keyset (cursor) pagination scales better for large datasets and streaming UIs. Implement sorting guarantees (stable, deterministic order), avoid client-driven arbitrary sorts on large datasets without indices, and consider projection queries to reduce payload size.

### 77. DTO vs Entity?

DTOs (Data Transfer Objects) and Entities serve different responsibilities: Entities model persistence concerns and lifecycle (managed state, lazy loading, relationships), while DTOs model API contracts or service boundaries. Exposing entities directly from controllers couples your API to the persistence model, risks lazy-loading exceptions, and may leak internal fields or security-sensitive data. Using DTOs enables shape optimization, versioning, and decoupling from ORM semantics.

At senior level, prefer mapping layers (MapStruct, custom mappers) to translate between Entities and DTOs, keep DTOs immutable where possible, and define explicit DTO versions for breaking changes. For performance-critical flows, use JPA projections or constructor queries to populate DTOs directly from SQL to avoid the cost and side effects of entity hydration.

### 78. Validation annotations?

Spring integrates with the Bean Validation API (JSR 380 — Hibernate Validator implementation) to declaratively validate DTOs and entities using annotations like `@NotNull`, `@Size`, `@Pattern`, `@Email`, and custom constraints. Use `@Valid` on controller method parameters to trigger validation. For complex rules, implement `ConstraintValidator` classes or group validations using validation groups.

Senior considerations: keep validation at the boundary (controller/service) and separate cross-field or business validation into service-layer checks rather than relying solely on annotations. Provide consistent error formats (structured validation error responses), localize messages via `ValidationMessages.properties`, and avoid using entity annotations for API validation if entity lifecycle diverges from API contract.

### 79. Spring Security basics?

Spring Security provides a comprehensive framework for authentication, authorization, and security-related concerns. Core concepts: `Authentication` (who the user is), `Authorization` (what they're allowed to do), `SecurityContext` (where the current principal is stored), and filters that intercept requests to perform authentication/authorization. Configure security via `WebSecurityConfigurerAdapter` (legacy) or the newer component-based DSL (`SecurityFilterChain` beans) and define authentication providers (in-memory, JDBC, LDAP, OAuth2).

At senior level, design defense-in-depth: enforce least privilege, use method-level security (`@PreAuthorize`) for fine-grained rules, centralize access rules, and use strong password storage (bcrypt/argon2). For microservices, prefer token-based authentication (JWT or opaque tokens validated centrally) and apply authorization at both API gateway and service boundary levels.

### 80. JWT authentication?

JWT (JSON Web Token) is a compact, self-contained token format carrying claims (subject, expiry, roles) and signed (HMAC or asymmetric keys). In Spring Security, JWTs are typically issued by an auth server at login and validated by resource services using the signing key or JWKS endpoint. JWTs enable stateless authentication: services don't need server-side sessions, which simplifies scaling and reduces central state.

Senior-level caveats: JWTs can't be revoked easily unless you maintain a token blacklist or use short expirations with refresh tokens. Use short-lived access tokens and rotate/secure refresh tokens; prefer asymmetric signing (RS256) for distributed architectures with multiple verifiers. Validate token expiry, audience, issuer, and signature, and avoid storing sensitive data in token claims.

### 81. OAuth basics?

OAuth 2.0 is an authorization framework enabling third-party apps to obtain limited access to resources on behalf of users. Key flows include Authorization Code (with PKCE for public clients), Client Credentials (machine-to-machine), and Refresh Token handling. OAuth separates authentication (often implemented via OpenID Connect) from authorization concerns.

At senior level, implement the appropriate grant for your scenario (Authorization Code + PKCE for SPAs/mobile, Client Credentials for backend services). Treat tokens as bearer tokens and protect transport with TLS. Use scopes to represent coarse-grained access, combine with fine-grained authorization in resource servers, and centralize token issuance and validation in a trusted auth server.

### 82. CSRF protection?

Cross-Site Request Forgery (CSRF) is an attack where a malicious site causes a user's browser to perform state-changing requests on a site where they're authenticated. CSRF protection relies on ensuring requests include a secret not accessible to third-party sites: synchronizer tokens (CSRF tokens), same-site cookies, or requiring explicit user interaction.

Spring Security enables CSRF protection by default for stateful sessions. For stateless APIs (JWT-based), CSRF is typically not necessary if cookies are not used for authentication; instead use Authorization headers and CORS restrictions. Use `SameSite` cookie attributes, require anti-forgery tokens on forms, and apply CSRF tokens only to endpoints that mutate state.

### 83. CORS handling?

CORS (Cross-Origin Resource Sharing) controls browser-enforced access for cross-origin requests. Configure CORS via `CorsConfigurationSource`, controller-level `@CrossOrigin`, or at the gateway level. Permit only trusted origins, restrict methods and headers, and avoid using wildcards (`*`) in production. For credentialed requests, set `Access-Control-Allow-Credentials` carefully and ensure allowed origins are explicit.

At scale, handle CORS at the edge (API gateway/CDN) to reduce load on application servers, enforce centralized origin validation, and log blocked requests for diagnostics.

### 84. Caching in Spring?

Spring Cache abstraction provides a consistent API (`@Cacheable`, `@CacheEvict`, `@CachePut`) while allowing pluggable backends (ConcurrentMap, Ehcache, Redis). Use caching to improve read performance for expensive or frequently accessed computations. Design cache keys deterministically, set appropriate TTLs, and ensure cache invalidation aligns with data mutation patterns to avoid stale reads.

Senior considerations: prefer explicit cache boundaries, monitor hit/miss ratios, and avoid caching highly dynamic or critical consistency-sensitive data. For distributed caches use Redis or Hazelcast and consider near-cache patterns for read-heavy workloads.

### 85. Redis integration?

Redis is a versatile in-memory datastore used for caching, pub/sub, rate limiting, and session storage. Integrate with Spring via `Lettuce` or `Jedis` clients and Spring Data Redis, which provides template and repository abstractions. Use Redis for fast lookups, distributed locks (Redisson), and lightweight message passing.

At senior level, design for Redis' memory constraints: use appropriate eviction policies, data encoding (HASHes for many small objects), and avoid storing large blobs. For high availability, use Redis Sentinel or clustered Redis; prefer `Lettuce` for non-blocking and scalability benefits. Monitor memory, latency, and key cardinality.

### 86. Spring profiles?

Spring profiles (`spring.profiles.active`) enable environment-specific configuration and bean registration. Annotate beans or configuration classes with `@Profile("dev")` to restrict them to environments. Use profiles to separate dev/test/production settings, but keep the number of profiles manageable and avoid environment-specific behavior spread across code. Prefer externalized configuration with `application-{profile}.yml` files and validate production profiles in CI/CD.

### 87. Configuration properties?

Spring's `@ConfigurationProperties` binds hierarchical configuration into typed beans, enabling type-safe configuration and validation via JSR-303. Use immutable configuration properties (constructor binding) and `@Validated` to ensure correctness. Store secrets in secure stores (Vault, AWS Secrets Manager) and avoid checking secrets into VCS. For multi-service deployments, centralize common configuration in a config server or use GitOps for consistency.

### 88. Bean scopes?

Bean scopes control lifecycle: `singleton` (one per container), `prototype` (new instance per request to container), `request`/`session` (web scopes), and `application`/`websocket` in specialized contexts. Prefer singletons for stateless services; use prototype for stateful short-lived beans but manage their lifecycle yourself (container won't call destroy callbacks). For web apps, use request/session scopes carefully and avoid storing heavy state in session-scoped beans.

### 89. Prototype vs singleton?

Singleton beans are container-managed single instances used for stateless services; prototype beans cause the container to create a new instance for each injection or retrieval. Use prototype for per-use mutable state or when instances carry request-specific data, but remember the container won't manage full lifecycle (destruction). Combine with `ObjectFactory` or `Provider` to obtain fresh instances on demand.

### 90. Circular dependency?

Circular dependencies arise when two or more beans depend on each other. Constructor-based injection prevents circular dependencies (good because cycles often indicate design issues). Field/setter injection can mask cycles that the container resolves via proxies. Address cycles by refactoring responsibilities, introducing an interface/adapter, using `@Lazy` injection, or breaking the cycle with an event-driven pattern. Treat circular dependencies as a design smell.

### 91. Spring AOP?

Spring AOP provides aspect-oriented programming via proxies that intercept method calls for cross-cutting concerns (transactions, security, logging). It supports method-level advice types (`@Before`, `@AfterReturning`, `@Around`) and uses either JDK dynamic proxies (interfaces) or CGLIB proxies (classes). Use `@Aspect` for modularizing cross-cutting logic and `Pointcut` expressions to target join points precisely.

Senior usage: minimize pointcut complexity, test aspects independently, and be aware of proxy boundaries (self-invocation bypasses proxies). For performance-critical code, ensure advice logic is lightweight and avoid excessive weaving or deep pointcuts that slow initialization.

### 92. Aspects and join points?

Aspects encapsulate cross-cutting behavior; join points are well-defined points in program execution (method execution, exception handler). Pointcuts select join points, and advice contains the code applied at those join points. Use expressive pointcut design to limit scope, prefer annotation-based pointcuts for clarity, and document AOP behavior to avoid surprising interactions.

### 93. Logging strategies?

Effective logging balances sufficient context with low overhead. Use structured logging (JSON) for observability, include correlation IDs, and avoid logging sensitive data. Centralize log configuration (Logback/Log4j2), route logs to aggregators (ELK, Loki), and implement log levels consistently. For performance, avoid expensive message construction at DEBUG level (use parameterized logging) and sample high-volume logs where appropriate.

### 94. Actuator usage?

Spring Boot Actuator exposes production-ready endpoints (health, metrics, info, env) and plugs into Micrometer for metrics. Use Actuator for health checks, readiness/liveness probes, and operational insight. Secure actuator endpoints, selectively expose endpoints, and integrate with monitoring systems (Prometheus, Datadog). Customize health indicators for downstream dependencies and keep health checks fast and non-blocking.

### 95. Health checks?

Health checks (readiness and liveness) signal service availability. Liveness checks verify the process is alive; readiness checks verify dependencies (DB, caches, external services) for accepting traffic. Implement lightweight readiness checks and avoid expensive or blocking checks during startup. For container orchestration (Kubernetes), wire readiness probes to signals that reflect real readiness and use startup probes to avoid premature restarts.

### 96. Async methods?

Spring supports asynchronous execution via `@Async` and configured `TaskExecutor`s. Use async for fire-and-forget tasks, non-blocking I/O integration, and offloading long-running jobs from request threads. Tune thread pools (core/max, queue sizes, rejection policies) according to task characteristics and propagate context explicitly (security, MDC) when needed. For complex workflows prefer message-driven or reactive approaches.

### 97. Scheduling?

Use `@Scheduled` for periodic tasks and `SchedulingConfigurer` for advanced control. For distributed systems, avoid running scheduled jobs on all instances unless intentional; use leader election, Quartz clustered scheduler, or external job services. Ensure idempotency of scheduled tasks, track last-run state, and provide operational controls for enabling/disabling tasks.

### 98. WebFlux basics?

Spring WebFlux is a reactive, non-blocking web framework built on Project Reactor and supports event-loop runtimes (Netty). It embraces Reactive Streams backpressure, providing `Mono` and `Flux` types for single/multi-value async flows. WebFlux is ideal for high-concurrency, I/O-bound applications where thread-per-request is too costly.

Senior guidance: design end-to-end reactive stacks (from client to DB/driver) to avoid blocking calls, use reactive drivers (R2DBC, reactive Redis), and benchmark carefully — reactive stacks shine for high concurrency with low-latency I/O but add complexity in reasoning and debugging.

### 99. Reactive vs blocking?

Blocking (thread-per-request) is straightforward and works well when concurrency is moderate and libraries are blocking (JDBC). Reactive systems use non-blocking I/O and asynchronous composition to scale with fewer threads and better resource utilization for I/O-bound workloads. However, reactive programming increases complexity, requires compatible non-blocking drivers, and complicates debugging and observability.

Choose blocking for CPU-bound or simple services and reactive for high-concurrency I/O-bound services where infrastructure and team expertise support it. Ensure metrics, tracing, and error handling are reactive-aware.

### 100. Thread pool tuning?

Thread pool tuning balances throughput, latency, and resource usage. Identify the workload type: CPU-bound (threads ~ number of CPU cores), IO-bound (more threads to tolerate blocking), or mixed. Configure pool size, queue type (bounded vs unbounded), keep-alive times, and rejection policies. Use monitoring (thread pool metrics, queue depth, task latency) and simulate production-like loads.

For web servers tune servlet container thread pools and connection pools (DB, HTTP clients) in tandem to avoid thread starvation. Prefer bounded queues with backpressure or adaptive throttling to prevent memory growth. Document rationale for sizes and provide knobs via configuration to adjust in production.

## Section 3 — Database (Q101–Q150)

### 101. SQL joins types?

SQL joins combine rows from multiple tables based on related columns. Types: INNER JOIN (only matching rows from both), LEFT JOIN (all from left, matched from right), RIGHT JOIN (all from right, matched from left), FULL JOIN (all from both), and CROSS JOIN (Cartesian product). Self-joins compare a table to itself for hierarchical structures. Understanding join semantics avoids incorrect results and performance issues.

At scale, query planners optimize join order and execution strategy; ensure filtered predicates are pushed down before joins to minimize intermediate row counts. Use EXPLAIN plans to verify join efficiency, and prefer star schemas (normalized fact and dimension tables) in data warehouses for join optimization. For high-volume queries, consider materializing joins into denormalized fact tables or caching common joined views.

### 102. Indexing strategies?

Indexes accelerate data retrieval by maintaining sorted key structures (B-trees, hash) pointing to rows. Create indexes on columns frequently used in WHERE, JOIN, and ORDER BY clauses. Single-column indexes are simple; composite indexes on (col1, col2) can optimize multi-column filters and sorts if columns are ordered correctly for the query.

Senior considerations: indexes slow writes (INSERT/UPDATE/DELETE) due to index maintenance, so balance read gains against write costs. Use EXPLAIN to confirm queries leverage indices and detect empty scans. Monitor index fragmentation and rebuild/reorganize periodically. Avoid excessive indices — maintain a lean index set aligned to query patterns.

### 103. Clustered vs non-clustered?

A clustered index determines the physical order of table rows on disk; each table has one clustered index (typically the primary key). Non-clustered indices are separate structures pointing to data rows. In SQL Server, clustered indices store the full row; in MySQL/InnoDB, the clustered index is the primary key and non-clustered indices point to it (by primary key).

Design clustered indices for range queries and joins. Select a narrow, stable, monotonically increasing column (often surrogate key) as the clustered key. Non-clustered indices supplement for other predicates and covered queries. Understanding the underlying storage model helps optimize query plans and avoid RID/key lookups.

### 104. Query optimization?

Query optimization involves choosing the most efficient execution plan. Use EXPLAIN/ANALYZE to inspect plans, ensure indices are used, and identify full table scans. Refactor queries to push predicates early, reduce intermediate rows, and leverage available indices. Avoid OR predicates on different indexed columns (use UNION if columns have indices) and be cautious with NOT IN (use NOT EXISTS for subqueries).

Distribute expensive computations: denormalize data at write time, use materialized views, or offload complex aggregations to analytical systems. Monitor slow query logs and profile execution times to identify bottlenecks. For large tables, consider partitioning or sharding and run analytical queries on read replicas.

### 105. Execution plan?

An execution plan shows how the database engine executes a query: the operation sequence (scans, seeks, joins, aggregations), row counts, and cost estimates. EXPLAIN PLAN (Oracle), EXPLAIN (MySQL/PostgreSQL), or SET STATISTICS IO/TIME (SQL Server) reveal the strategy the optimizer chose. Plans include node costs, estimated vs actual rows (indicating cardinality estimation errors), and index usage.

Analyze plans to detect inefficiencies: full table scans on large tables, nested loops on large datasets (prefer hash or merge joins), or missing indices. Cardinality mismatches (estimated vs actual rows) suggest stale statistics or complex filter predicates. Use execution plan comparisons to validate optimization improvements.

### 106. ACID properties?

ACID guarantees data integrity: Atomicity (all-or-nothing), Consistency (valid state transitions), Isolation (concurrent transactions don't interfere), and Durability (committed changes persisted). Most relational databases implement ACID natively. NoSQL and distributed systems often weaken ACID guarantees for scale; BASE (Basically Available, Soft state, Eventually consistent) is common in distributed systems.

For mission-critical applications ensure ACID at the database layer. For high-scale, design for eventual consistency and use compensating transactions or idempotency semantics where strict ACID is unattainable. Understand your database's ACID implementation and limitations (e.g., distributed transactions are expensive).

### 107. Isolation levels?

Isolation levels control concurrent transaction visibility and phenomena prevention. READ UNCOMMITTED (dirty reads), READ COMMITTED (no dirty reads), REPEATABLE READ (no dirty/non-repeatable reads), and SERIALIZABLE (prevents phantom reads). Most databases default to READ COMMITTED balancing consistency and concurrency.

Choose based on consistency needs: REPEATABLE READ for most applications, SERIALIZABLE for critical atomic operations (stock reduces + payment). Be aware of performance costs: higher isolation levels require more locking, reducing concurrency. Use MVCC (multi-version concurrency control) databases like PostgreSQL for better isolation without locking overhead.

### 108. Deadlocks in DB?

Deadlocks occur when two transactions wait cyclically for locks. Prevent using lock ordering (always acquire locks in a consistent order), timeouts, or deadlock detection and rollback. Design transactions to be short, minimal and avoid acquiring locks in user-initiated sequences.

Detect deadlocks via logs or monitoring and analyze to identify victims. Implement retry logic with backoff for deadlock victims. For high-contention scenarios, redesign to reduce shared locks (e.g., row-level versioning, sharding by transaction ID).

### 109. Normalization vs denormalization?

Normalization (1NF, 2NF, 3NF, BCNF) reduces data redundancy and anomalies via structured dependency rules. Denormalization intentionally repeats data to optimize queries, reducing joins and improving read performance at the cost of write complexity and storage.

Most OLTP systems are normalized for consistency; OLAP/analytics lean toward denormalized star schemas for query speed. Hybrid approaches use normalized transactional databases with denormalized analytical data warehouses (ETL/ELT pipelines). Choose based on workload: normalize for frequent writes, denormalize for read-heavy analytics.

### 110. Foreign keys?

Foreign keys enforce referential integrity: a column references a primary key in another table, preventing orphaned rows. They ensure data consistency but add constraint checks on writes. Use foreign keys in OLTP systems to maintain integrity; in high-write scenarios, trade foreign keys for application-level consistency or eventual consistency via async reconciliation.

Design foreign key cascades (ON DELETE CASCADE, ON UPDATE CASCADE) carefully — unintended cascades can cause mass deletions. Archive/soft-delete patterns may work better than cascading deletes for audit trails.

### 111. Transactions?

Transactions group multiple operations into an atomic unit that either fully succeeds or fully fails. BEGIN/COMMIT/ROLLBACK control transaction boundaries. Transactions ensure ACID semantics, but extending transactions (large batches, long operations) causes lock contention.

Design short transactions targeting specific business operations. Use savepoints for partial rollbacks. Monitor transaction duration and lock waits. For distributed transactions (across multiple DBs), implement compensating transactions or saga patterns instead of expensive distributed hashes.

### 112. Stored procedures?

Stored procedures are precompiled SQL code executed on the database server. They can encapsulate business logic, improve performance (reduced network round-trips), and provide security (execution via permissions). However, they couple business logic to the database, complicate versioning, and reduce testability.

Modern practices prefer application-layer logic for testability and maintainability; use stored procedures for complex, frequently executed operations or when the database must enforce invariants. Document procedures well and version-control scripts alongside application code.

### 113. NoSQL vs SQL?

SQL databases (relational, normalized, ACID) excel at complex queries and consistency. NoSQL (key-value, document, graph, time-series) prioritizes scale, flexibility, and write performance, often relaxing consistency. SQL suits transactional workloads; NoSQL suits massive-scale, flexible-schema, or specialized data (graphs, time-series).

Many modern systems use polyglot persistence: SQL for transactional core, NoSQL for caches/logs/analytics. Choose based on data model, consistency requirements, and scale. Technology selection should drive database choice, not vice versa.

### 114. MongoDB basics?

MongoDB is a document database storing JSON-like documents in collections (like tables). Flexibility: no fixed schema, nested documents, flexible queries. Horizontal scaling via sharding. However, no joins (denormalize instead), weaker consistency, and transactions are recent additions.

Use MongoDB for rapidly evolving schemas, high-write scenarios, or when a document model fits the domain. For relational data (many-to-many, complex joins), SQL is better. Manage consistency via application logic or multi-document transactions (newer versions).

### 115. Redis use cases?

Redis is an in-memory key-value store used for caching, sessions, rate limiting, pub/sub, and leaderboards. Extremely fast for gets/sets. Use Redis where latency matters and data fits in memory.

Limitations: volatile (can lose data on restart; use persistence/replication), memory-bounded, and limited query flexibility compared to SQL. Suitable for real-time features (live counters, caches), not persistent critical state unless replicated.

### 116. Caching strategies?

Cache-aside (lazy loading): application fetches from cache, misses go to DB. Write-through: write to cache and DB. Write-behind: write to cache, async to DB (risk of loss). Cache invalidation is hard: use TTL, versioning, or event-driven invalidation. Minimize thundering herd (cache stampedes) via request coalescing or probabilistic early expiry.

Design cache keys deterministically and monitor hit ratios. Avoid caching mutable, frequently-changing data. For distributed caches (Redis, Memcached), handle partial failures gracefully.

### 117. Sharding?

Sharding horizontally partitions data across multiple database instances by a shard key (e.g., user ID mod N). Increases write capacity and query parallelism. Challenges: shard key selection (poor key causes hotspots), migration between shards, cross-shard queries (expensive), and transaction complexity.

Choose keys with even distribution and low cardinality changes. Avoid reshuffling shards; use consistent hashing or fixed schemas. Implement application-level routing or use a shard proxy/database gateway.

### 118. Replication?

Replication copies data across multiple database instances: primary (writes), replicas (reads). Improves availability and read throughput via read replicas. Consistency models vary: synchronous (strong but slow), asynchronous (fast but eventual).

Monitor replication lag carefully. Use read replicas for analytics/reporting only if eventual consistency is acceptable. For high availability, use multi-master replication (complexity) or failover automation (primary election). Test failover scenarios regularly.

### 119. Read replicas?

Read replicas are copies of the primary database accepting only reads, offloading read traffic from the primary. Useful for scaling read-heavy workloads and analytics without impacting transactional performance. Consistency is eventual (replication lag).

Design read routes carefully: route strong-consistency reads to primary, weak-consistency to replicas. Handle replica failures transparently. Monitor lag and alert on high lag to prevent stale data surprises.

### 120. CAP theorem?

CAP states a distributed system can guarantee only two of three: Consistency (all nodes see the same data), Availability (system always responds), or Partition tolerance (survives network partitions). Real systems must tolerate partitions, so they trade Consistency (CP) or Availability (AP).

CP systems (strong consistency, unavailable during partitions): suitable for critical financial/transactional data. AP systems (eventual consistency, always available): suitable for social/content systems. Design explicitly choosing your CAP trade-off and ensure the entire system (app, DB, replication) aligns.

### 121. Eventual consistency?

Eventual consistency guarantees that absent further writes, all replicas converge to the same state given sufficient time. Weaker than strong consistency but enables high availability and partition tolerance. Risk: stale reads, write conflicts (especially multi-master).

Implement conflict resolution (last-write-wins, application logic, CRDTs) for multi-master. Use version vectors or timestamps to track causality. Suitable for caches, social feeds, analytics; avoid for transactional or financial data without compensating mechanisms.

### 122. Pagination strategies?

OFFSET-based pagination (skip N, take M) is simple but slow for deep offsets (expensive skip). Keyset/cursor pagination fetches the next batch after a known record, scaling to large datasets. Use deterministic sort order and a unique identifier.

For REST APIs, expose cursors (Base64-encoded last key) or use Link headers. For UI, keyset is better for large datasets; OFFSET works for moderate result sets. Implement sort stability to avoid duplicate/missing rows.

### 123. Bulk operations?

Bulk INSERT/UPDATE operations (batch uploads) are faster than individual operations: reduced round-trips, transaction overhead, and resource utilization. Use bulk operations for ETL, imports, or daily reconciliations.

Batch sizes depend on row size and available memory; typical: 1000-10000 rows. Monitor locks and query load. For very large imports, use database-specific tools (COPY in PostgreSQL, LOAD DATA in MySQL) or parallel loading. Disable indices during bulk loads, then rebuild.

### 124. Data migration?

Data migration moves data between systems (DB upgrades, consolidation, schema evolution). Plan carefully: backward compatibility (dual-write), validation (row counts, checksums), and rollback procedures. Use dark launch patterns: run new system in parallel, validate, then cutover.

Minimize downtime: online migrations (trigger-based dual-write) are preferable to offline. Validate data integrity post-migration with automated checks. Document the migration process for repeatability.

### 125. Backup strategies?

Regular backups protect against data loss. Types: full (entire database), incremental (changes since last), and differential (changes since last full). Frequency depends on RPO (Recovery Point Objective) and RTO (Recovery Time Objective).

Test restores regularly to ensure backups work. Use off-site/cloud backups for disaster recovery. Implement automated backup verification and monitor backup duration and size. For high-availability systems, combine backups with replication for rapid recovery.

### 126. Soft delete vs hard delete?

Soft delete (mark as deleted, don't remove) preserves data for auditing and recovery. Hard delete removes rows entirely. Soft deletes enable audits and undo; hard deletes save storage and simplify queries (filter out deleted rows in all queries).

Use soft deletes for compliance/audit requirements or when undo is likely. Use hard deletes for privacy-sensitive data or when storage is a constraint. Implement both: soft delete initially, archival hard delete after a retention period.

### 127. Audit logging?

Audit logs track changes: who changed what, when, and why. Implement via triggers (DB-level), application-layer logging, or event sourcing. Logs should be immutable and queryable.

Design for compliance (GDPR, SOX, HIPAA) if required. Store in a separate, read-only system. Aggregate for analytics (who accessed what, what changed) to detect anomalies. Index heavily for audit queries.

### 128. Index performance impact?

Indices accelerate reads but slow writes (INSERT/UPDATE/DELETE must update indices). Unused indices consume space and hurt write performance. Monitor query plans and index usage; drop unused indices.

Balance: too few indices cause slow reads, too many cause slow writes and wasted space. Maintain the smallest index set supporting high-impact queries. Use covering indices (all columns needed by a query in the index) to avoid key lookups.

### 129. Composite indexes?

Composite indices on (col1, col2, col3) optimize queries filtering on col1, col1+col2, or col1+col2+col3 (left-prefix rule). Order columns by selectivity and query patterns. A composite index can eliminate joins if all needed columns are present (covering index).

Design composites carefully: the order matters for performance. Avoid over-indexing — review query patterns and avoid redundant composites.

### 130. Optimistic vs pessimistic locking?

Optimistic locking assumes conflicts are rare; uses version columns or timestamps to detect conflicts on write. Pessimistic locking acquires locks upfront before reading (SELECT FOR UPDATE). Optimistic suits low-contention scenarios and distributed systems; pessimistic suits high contention and ensures immediate consistency.

Choose based on workload characteristics. Implement optimistic with retry logic; pessimistic requires careful lock ordering to avoid deadlocks. Most Web/mobile apps use optimistic locking for better concurrency.

### 131. REST best practices?

Design REST APIs around resources (nouns), not actions (verbs). Use HTTP methods meaningfully: GET (safe, idempotent), POST (create), PUT (replace), PATCH (partial update), DELETE (remove). Status codes convey results: 200 (OK), 201 (Created), 204 (No Content), 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found), 500 (Server Error).

Version APIs (Accept header, URL path, or query param) and maintain backward compatibility. Implement pagination, filtering, sorting server-side. Use HAL/JSON:API for hypermedia. Document with OpenAPI/Swagger. Rate limit and throttle. Test with curl/Postman or automated suites.

### 132. Idempotent APIs?

Idempotent operations return the same result if executed multiple times (GET, PUT, DELETE are idempotent; POST is not). For safety, POST should be idempotent via idempotency keys: client sends a unique key, server de-duplicates retries.

Implement server-side idempotency stores (in-memory, Redis) keying on (client_id, idempotency_key) mapping to the response. Timeout/evict old entries. Critical for payment, booking, and state-changing operations where retries can occur due to network failures.

### 133. API versioning?

Multiple strategies: URL path (`/v1/users`), Accept header (`Accept: application/vnd.api+json; version=1`), query parameter (`?api-version=1`). URL path is explicit and SEO-friendly; headers are simpler operationally.

Plan for evolution: add optional fields (no breaking), deprecate old endpoints gradually, coordinate with clients. Semantic versioning (major.minor.patch) signals compatibility. Support multiple versions simultaneously during transition to avoid forced client upgrades.

### 134. Rate limiting?

Rate limiting restricts request frequency per client to prevent abuse and ensure fair resource allocation. Algorithms: token bucket (fixed rate, burst allowance), leaky bucket (smooth rate), sliding window (precise but stateful).

Implement at API gateway or application layer. Store limits in distributed store (Redis) for multi-server consistency. Return 429 (Too Many Requests) with Retry-After headers. Vary limits by tier (free, premium) and endpoint sensitivity. Monitor and alert on high-rate clients.

### 135. API gateway?

API gateways sit between clients and microservices, handling cross-cutting concerns: authentication, rate limiting, request routing, transformation, caching, and logging. Popular: Kong, AWS API Gateway, nginx, Spring Cloud Gateway.

Gateways reduce coupling and enable traffic shaping. Use them for versioning, request validation, response transformation, and service discovery. However, they're another component to operate; minimize custom logic in the gateway. For microservices, gateways are essential for unified entry points and common policies.

### 136. Microservice communication?

Direct service-to-service calls (REST, gRPC) are synchronous and simple but couple services and require resilience patterns (retries, timeouts, circuit breakers). Async messaging (event bus, message queue) decouples services but adds complexity (eventual consistency, ordering).

Design based on coupling tolerance and consistency needs. Prefer async for non-time-critical operations (email, notifications); sync for user-facing reads. Use service mesh (Istio) for transparent resilience and observability without client code changes.

### 137. Circuit breaker?

Circuit breakers prevent cascading failures by stopping requests to a failing service and returning errors/defaults instead. States: Closed (normal, request passes), Open (failing, request fails immediately), Half-Open (testing recovery, allowing probe requests).

Tune thresholds (failure rate, count) and timeouts to reflect recovery times. Pair with retries, timeouts, and fallbacks. Libraries: Resilience4j, Hystrix. Monitor circuit state and alert on frequent opens to catch issues early.

### 138. Resilience4j?

Resilience4j is a lightweight library providing resilience patterns: circuit breakers, retries, timeouts, bulkheads, and rate limiters. It's event-driven, composable, and has low overhead.

Use circuit breakers for external calls, retries with exponential backoff for transient failures, timeouts to prevent hanging threads, bulkheads to isolate resources, and rate limiters to control load. Integrate with Spring for decorators on methods or explicit use via APIs. Monitor metrics and logs for circuit state, retry counts, and timeouts.

### 139. Message queues?

Message queues decouple producers and consumers: producers send messages, queues persist them, consumers process asynchronously. Benefits: decoupling, scalability, and resilience. Drawbacks: eventual consistency, debugging complexity, and operational overhead.

Popular: RabbitMQ (AMQP), Apache Kafka (event streaming), AWS SQS, Google Cloud Pub/Sub. Choose based on throughput, message ordering, durability, and consumer patterns. Implement at-least-once delivery guarantees and idempotent consumers. Monitor queue depth and consumer lag.

### 140. Kafka basics?

Kafka is a distributed event streaming platform: producers publish records to topics (sharded into partitions), consumers read sequentially from partitions. Scales to millions of events/sec with low latency.

Partition key determines placement; messages in a partition are ordered. Consumer groups enable parallel consumption. Kafka retains messages (logs), enabling replay. Use for event sourcing, streaming analytics, and high-volume data pipelines. Operational complexity is higher; ensure monitoring, backup, and capacity planning.

### 141. Event-driven architecture?

Event-driven systems emit domain events (DomainEvent objects, JSON messages) capturing state changes. Services subscribe to event streams, triggering reactions (notifications, data syncs). Enables loose coupling and scalability.

Implement event publishing (application code, database triggers, log-based CDC), event bus (message queue, event store), and event subscribers. Ensure idempotency (by event ID), order (per aggregate), and retention (audit trail). Event versioning handles schema evolution. Complexity: eventual consistency, debugging distributed flows, testing.

### 142. Saga pattern?

Sagas coordinate multi-service transactions without distributed commits. Orchestration: a central service directs steps (e.g., payment service charges, inventory service reserves). Choreography: services publish events and react to others' events.

Implement compensating transactions for rollback (reverse charges if reservation fails). Sagas tolerate temporary inconsistency and partial failures better than 2-phase commits. Design idempotent service calls and careful event ordering.

### 143. Distributed transactions?

Distributed transactions across multiple services are expensive and fragile. Two-phase commit (2PC) blocks participants during voting, vulnerable to failures. Avoid in high-latency environments.

Prefer eventual consistency via sagas, event-driven patterns, or accept eventual inconsistency. If strict ACID is necessary, keep transactions local (single service). Design for single-version truth: one service owns a data model, others replicate.

### 144. Service discovery?

Service discovery automatically locates service instances (IP, port) enabling dynamic routing without hardcoded addresses. Pull-based: clients query a registry (Eureka, Consul); push-based: registry notifies clients.

Use with load balancers for traffic distribution. Important for container/cloud deployments where instances are ephemeral. Implement health checks ensuring registered instances are healthy. Coordinate with service mesh for transparent discovery and resilience.

### 145. Config server?

Config servers (Spring Cloud Config, Consul, etcd) centralize configuration enabling dynamic updates without redeployment. Clients pull or subscribe to config changes.

Store sensitive configs (secrets) in secure stores (Vault) separate from code. Version config alongside app code for traceability. Use profiles (dev, prod) to vary settings per environment. Implement config refresh strategies (poll, webhook) and test configuration changes in staging.

### 146. Load balancing?

Load balancers distribute traffic across multiple servers optimizing resource utilization and availability. Algorithms: round-robin (sequential), least connections (lowest active), IP hash (sticky sessions), weighted (server capacity).

Deploy at different layers: HTTP (Layer 7) for URL-based routing, TCP (Layer 4) for protocol-agnostic balancing. Use health checks ensuring live backends. For microservices, leverage client-side load balancing (Ribbon, Spring Cloud LoadBalancer) or service mesh.

### 147. Blue-green deployment?

Blue-green deployment runs two identical production environments: blue (current), green (new). Cut traffic after validating green, enabling fast rollback if issues arise.

Requires load balancer switchover and stable databases (shared or replicated). Zero-downtime deployments and rapid rollbacks are benefits. Operational cost: running dual environments. Coordinate with CI/CD pipelines to automate validation and switchover.

### 148. Backend performance tuning?

Performance tuning involves identifying bottlenecks and optimizing. Profile CPU, memory, I/O using APMs (Datadog, New Relic), JVM profilers (YourKit, JProfiler), and database slow logs. Common bottlenecks: slow queries, GC pauses, blocked threads, inefficient algorithms.

Optimize incrementally: measure before/after to confirm improvements. Focus on high-impact items (hottest code paths). Use caching, batch operations, connection pooling, and async processing. Keep performance regressions from creeping in via continuous monitoring and load testing.

### 149. Distributed Systems Overview

Distributed systems span multiple machines and require handling: partial failures, latency, eventual consistency, and operational complexity. CAP theorem guides consistency trade-offs. Design for fault tolerance via redundancy, health checking, and automated failover.

Plan for the human element: operational runbooks, incident response playbooks, and on-call rotations. Test failure scenarios (chaos engineering). Monitor deeply (metrics, logs, traces) to enable rapid diagnosis. Scale horizontally (multiple servers) rather than vertically (larger machines) for resilience and cost-effectiveness.

### 150. High Availability Architecture

High availability (HA) systems tolerate component failures and maintain service. Patterns: redundancy (N+1 servers), load balancing (distribute traffic), health monitoring (detect failures), automated failover (elect new leader if primary fails), and coordination (ZooKeeper, etcd).

Design for graceful degradation: shed non-critical features under load to maintain core functionality. Use RTO (Recovery Time Objective) and RPO (Recovery Point Objective) to guide redundancy and backup strategies. Test failover regularly. For critical systems, multi-region replication and disaster recovery procedures are essential. Document runbooks for common failure scenarios.

## Section 4 — React / Frontend (Q151–Q200)

### 151. Virtual DOM?

The Virtual DOM is React's in-memory representation of the UI (a lightweight JavaScript object tree mirroring the DOM). React renders components to vDOM, compares (diffs) the new vDOM with the previous one, determines minimal updates, and reconciles those changes to the real DOM. This abstraction decouples rendering logic from direct DOM manipulation and enables efficient batching of updates.

Benefits: abstracts browser differences, improves performance via diffing/batching, and enables advanced features (SSR, native rendering). The cost: vDOM creation and diffing logic. For most apps, vDOM overhead is negligible compared to DOM operations. Understanding reconciliation prevents subtle bugs (key selection, conditional mounting).

### 152. Reconciliation?

Reconciliation is React's algorithm for updating the UI when state/props change. React diffing: if elements have different types (div vs span), rebuild; if same type, preserve the DOM node and diff attributes/children. Keys help identify elements across re-renders, essential for lists (without keys, React may re-render unrelated items).

Reconciliation is heuristic-based (O(n), not optimal), suitable for most UIs. Understand key selection: stable, unique identifiers (IDs), not indices. Poor keys cause re-mounts, losing component state and refs. This is a common source of subtle bugs in React apps.

### 153. React lifecycle?

Class component lifecycle phases: mounting (constructor, render, componentDidMount), updating (render, componentDidUpdate on prop/state change), and unmounting (componentWillUnmount). Hooks replicate lifecycle via useEffect dependencies and cleanup functions.

Lifecycle is essential for managing side effects (API calls, subscriptions), animations, and cleanup. Mismanagement (missing cleanup, wrong dependencies) causes memory leaks and unwanted re-renders. Prefer functional components with hooks; lifecycle is simpler and more composable with hooks.

### 154. Hooks rules?

Rules of Hooks (enforced by ESLint): only call hooks at the top level of components/custom hooks (not conditionally or in loops), and only in React functions, not regular JS. Violations break React's ability to track hook state per component.

These rules enforce a consistent call order enabling React to map hook state to functional closures. Violators cause "rules of hooks" linting errors. Use custom hooks to encapsulate stateful logic and compose behaviors safely.

### 155. useState batching?

React batches state updates in event handlers (click, input) and lifecycle methods, applying all updates in a single render to improve performance. Outside these contexts (promises, timeouts, certain events), updates may not batch (React 18 introduces automatic batching in more scenarios).

Batching reduces re-renders but can surprise developers expecting immediate state updates. For imperative updates or when immediate reads are needed, use flushSync() (React 18+). Understanding batching avoids state update surprises.

### 156. useEffect lifecycle?

useEffect runs side-effect logic after component renders and handles cleanup. Dependencies array controls when the effect re-runs: empty = once on mount, [deps] = when deps change, omitted = every render. Return a cleanup function to undo side effects (unsubscribe, cancel timers).

Common pitfall: forgetting cleanup causes memory leaks (subscriptions leaking, timers persisting). Incorrect dependencies cause stale closures and ineffective logic. Use React DevTools Profiler to detect unnecessary effect runs. For complex effects, consider useReducer or custom hooks.

### 157. useMemo vs useCallback?

useMemo memoizes computations: `useMemo(() => expensiveCalc(a, b), [a, b])` caches results if deps unchanged. useCallback memoizes function references: `useCallback(() => handleClick(), [deps])` ensures stable function identity across renders.

Use when passing to memoized children (prevent unnecessary re-renders) or as dep for other hooks. Overuse adds overhead (dependency tracking, memory for cached values). Profile before optimizing; often unnecessary. Both are tools to optimize after identifying real performance bottlenecks via React Profiler.

### 158. useRef usage?

useRef creates a mutable reference persisting across renders without triggering re-renders: `const inputRef = useRef(null); inputRef.current.focus()`. Use for direct DOM access (input focus, measuring, playing video), stable timers, or storing mutable values decoupled from render.

Abuse (storing derived state in useRef) leads to inconsistent UIs. Refs are escape hatches; prefer declarative state and props when possible. Use refs for truly imperative needs (canvas, audio, unmeasurable values).

### 159. Custom hooks?

Custom hooks are JavaScript functions starting with "use" that call built-in hooks, extracting reusable stateful logic. Example: `useFormInput` encapsulates input state and handlers. Hooks compose: a custom hook can call other hooks.

Custom hooks improve reusability, testability, and separation of concerns. Test them like pure functions (inputs → outputs). Share hooks across projects via packages for maximum reuse. Keep custom hooks simple and composable; complex logic belongs in custom hooks, not components.

### 160. Controlled components?

Controlled components manage form input state in React state, making the UI state source of truth. Uncontrolled components store state in the DOM (ref-based).

Controlled components enable instant validation, conditional submission, and integration with application state. Uncontrolled components are simpler for simple forms without validation. For most modern apps, controlled components are standard; libraries (Formik, React Hook Form) ease management of many inputs.

### 161. Context API?

Context enables passing data deeply through component trees without prop-drilling. Create context (`React.createContext`), provide a value at a parent, and consume via `useContext(Context)`. Avoids passing props through intermediate components.

Overuse of Context couples far-apart components and makes data flow implicit. Each context change causes all consumers to re-render (no granular subscription). For larger state, prefer Redux or local state management. Context works well for global concerns (theme, language, auth).

### 162. Redux architecture?

Redux is a predictable state container: single immutable state tree, actions describe changes, reducers compute new state from old state + action, and a store coordinates everything. Middleware (Redux Thunk, Redux Saga) handles async logic.

Benefits: predictable state mutations, time-travel debugging, testability. Drawbacks: boilerplate, learning curve, overkill for simple apps. Modern alternatives (Context + Hooks, Zustand, Jotai) offer lighter state management. Use Redux when the app is complex and benefits from centralized, predictable state.

### 163. Redux Toolkit?

Redux Toolkit simplifies Redux: `createSlice` bundles actions + reducer + selectors; `createAsyncThunk` handles async data; `configureStore` sets up middleware and DevTools. Reduces boilerplate significantly.

Modern Redux development uses Toolkit; it's the recommended way. Immer integration enables "mutative" reducer syntax that's actually immutable under the hood. Learn Redux Toolkit for Redux applications.

### 164. Middleware?

Middleware in Redux intercepts actions before reducers, enabling async operations, logging, or action transformation. Redux Thunk dispatches async action creators returning functions; Redux Saga uses generator functions for complex async flows and cancellation.

Middleware is powerful but adds complexity. For simple apps, consider simpler alternatives (useEffect for side effects, local state). Test middleware separately from components. Compose middleware for reusability.

### 165. Async flow?

Handling async data (API calls, timers) requires coordinating state changes before/after operations. Redux Thunk: dispatch a function that fetches data, dispatches loading/success/error actions. Redux Saga: watchers listen for actions, fork side effects (fetch), handle results.

Modern approaches: React Query/SWR manage server state separately from app state, simplifying async data handling. useEffect for simple cases. Understand data fetching patterns (requests, caching, error handling) and choose the tool fitting your scale.

### 166. React Query?

React Query manages server state (API data, caching, synchronization). Replace Redux for server state with hooks like `useQuery`, `useMutation`. Built-in caching, refetching, deduplication, and background updates reduce boilerplate significantly.

Benefits: separation of client vs server state, automatic refetch on focus/mount, optimistic updates, pagination support. Pairs well with Redux (client state) or local state. Reduces async complexity in most apps. Consider React Query first for data fetching before Redux.

### 167. Server vs client state?

Server state (API data, DB records) is owned by the server; client state is local (form values, UI flags, selections). Mixing them causes sync issues. React Query / SWR manage server state (fetch, cache, sync); useState/Redux manage client state.

Design clear boundaries: server state lives in React Query/cache, client state in React state/context. Avoid duplicating server state in Redux (causes staleness). This separation simplifies reasoning and updates.

### 168. Performance optimization?

React optimizations: memoize components (React.memo), lazy-load with code splitting, virtualize long lists, defer non-critical updates (useTransition). Profile with React DevTools Profiler to identify slow renders or unnecessary re-renders.

Common bottlenecks: re-rendering children (use keys, memo), expensive computations (useMemo), N+1 queries (batch requests), large bundles (code split, tree-shake). Avoid premature optimization; measure first. Most React apps are fast enough with proper patterns (memoization, virtualization, code splitting).

### 169. Memoization?

Memoization caches results of expensive computations. In React: React.memo memoizes components, useMemo caches values, useCallback caches functions. Benefits: skip re-renders/recalculations if inputs unchanged.

Downsides: memory for cached values, dependency tracking overhead, potential bugs if deps are wrong. Profile before memoizing. Often premature optimization. Use when profiling shows bottlenecks or passing to memoized children.

### 170. Prevent re-renders?

Use React.memo for components unchanged unless props change. useMemo for expensive child props. useCallback for stable callbacks. Keys for list items to prevent unrelated items re-rendering. Context selectors (custom hooks) to subscribe only to relevant state.

Over-memoizing complicates code. Focus on structural optimizations (components, keys, state locality) before micro-optimizations. Profile to verify improvements.

### 171. Code splitting?

Code splitting breaks bundles into chunks loaded on-demand, reducing initial load. Use `React.lazy` + `Suspense` for route-based splitting (each route is a chunk). Tool-level: webpack automatically splits by async imports.

Benefits: faster initial page load, lazy evaluation of code. Drawbacks: complexity, potential waterfall loads. For most SPAs: split at route boundaries. For components, split heavy libs (editors, charts) as needed.

### 172. Lazy loading?

Lazy loading of components/images defers loading until needed. `React.lazy` for dynamic imports; `Suspense` shows fallback. Images: `IntersectionObserver` or library (react-lazyload, react-intersection-observer) to load when visible.

Benefits: faster initial load, reduced bandwidth. Drawbacks: complexity, potential "blank" states. Use at route and heavy component boundaries. For list virtualization, lazy-loading images in viewports is essential.

### 173. Suspense?

Suspense is React's mechanism for handling async operations in a declarative way. Wrap lazy components/async code with `<Suspense fallback={<Loader/>}>`. When suspended (loading), fallback renders; when ready, component renders.

Suspense simplifies async handling but is relatively new and not mature for general data fetching (use React Query instead). For data fetching, libraries wrap Suspense usage. Expect Suspense to evolve as React Concurrent features stabilize.

### 174. Error boundaries?

Error boundaries catch JavaScript errors in child components and display fallbacks (error UI, logs). Implemented as class components with `componentDidCatch` or `getDerivedStateFromError`.

Use to gracefully handle errors (render fallback instead of crashing). Don't catch event handler errors (use try/catch), async errors (React 16 limitation), or server-side errors. Combine with error reporting services (Sentry) to track production errors.

### 175. React concurrent rendering?

React Concurrent features enable non-blocking rendering: the main thread isn't blocked during large renders. useTransition marks non-urgent updates (can be interrupted if higher-priority work arrives). useDeferredValue defers a value update for lighter re-renders.

Benefits: faster interactions despite heavy renders. Downsides: complex mental model, potential inconsistency between renders if refs access state mid-render. Experimental; use when profiling shows main-thread blocking from renders.

### 176. Transition API?

useTransition marks updates as non-urgent transitions that don't block the UI. `startTransition(() => setState(...))` marks the update as a transition, allowing interruption by urgent updates (user input).

Use for search filtering, pagination, or expensive re-renders. Benefits: responsive UI despite heavy computations. Requires understanding concurrent rendering; use profiling to validate improvements.

### 177. useDeferredValue?

useDeferredValue defers updating a value "later", allowing higher-priority updates to interrupt. Useful for keeping rendered content fresh while deferring expensive operations on updated data.

Similar to useTransition but for values instead of imperative updates. Use for lists with expensive filtering/sorting deferred while UI stays responsive. Concurrent feature; validate improvement via profiling.

### 178. Component design patterns?

Patterns: Container (logic, state) + Presentational (UI only) for separation, Render Props (function as child for state sharing), Higher-Order Components (HOC, wrap for behavior addition), Custom Hooks (modern composition). Compound components expose sub-components for flexible composition.

Modern React favors Hooks + functional components. Render Props and HOCs are older patterns now replaced by Hooks for simplicity. Compound components remain useful for flexible libraries (Headless UI).

### 179. Compound components?

Compound components expose sub-components sharing implicit state (context): `<Select><Select.Option value="1"/></Select>`. Sub-components access parent state via context. Enables flexible composition while centralizing logic.

Benefits: intuitive API, flexible composition. Use for libraries/component groups. Popular in Headless UI and design systems.

### 180. HOC vs hooks?

Higher-Order Components (HOCs) wrap a component to add behavior. Custom Hooks extract stateful logic for reuse. Hooks are preferred: simpler, fewer performance pitfalls (no wrapper hell), easier reasoning.

HOCs remain useful for libraries needing deep component control (Redux connect), but Hooks (useConnect or hooks API) are more modern. Migrate away from HOCs when possible.

### 181. Render props?

Render Props is a pattern where a component accepts a function prop that returns JSX. `<DataFetcher render={data => <Child data={data}/>}/>`. Enables state sharing without HOC wrapper hell.

Hooks replaced Render Props for most use cases. Render Props remain useful in some library contexts but are less common now.

### 182. Form handling?

Options: controlled components (setState per input), Formik, React Hook Form, or useReducer for complex forms. Controlled forms integrate easily with React; they require validation, submission, and error handling.

React Hook Form is lightweight and performant (minimal re-renders); Formik is feature-rich (validation, async). Choose based on complexity. For custom forms, controlled components suffice. For large forms, use a library.

### 183. Validation libraries?

Libraries: Formik (validation + form state), React Hook Form (lightweight, hook-based), Yup/Zod (schema validation). Client-side validation improves UX; always validate server-side for security.

Combine libraries: React Hook Form + Zod for lightweight, type-safe validation. Or custom validation logic for simple apps. Validate on blur/submit depending on UX goals.

### 184. Accessibility?

Accessibility (a11y) ensures apps work for users with disabilities. Semantic HTML (button instead of div), ARIA labels, keyboard navigation, sufficient color contrast, and screen reader support. Use tools: axe, Lighthouse, WAVE.

React apps often break a11y by misusing divs, ignoring focus management, or skipping labels. Treat a11y as first-class. Test with screen readers (NVDA, JAWS). Many a11y issues are cheap to fix if caught early.

### 185. ARIA?

ARIA (Accessible Rich Internet Applications) adds semantic metadata via attributes (role, aria-label, aria-hidden) helping assistive tech understand dynamic content. Use when semantic HTML isn't sufficient.

Don't overuse ARIA; prefer semantic HTML (button, nav, section). Use aria-live for dynamic updates, aria-expanded for toggles, aria-label for icon buttons. Validate ARIA via axe or similar tools.

### 186. CSS architecture?

CSS approaches: BEM (Block-Element-Modifier) for scalable class naming, CSS Modules (scoped styles), CSS-in-JS (styled-components, emotion), or utility-first (Tailwind). Each trades-off between reusability, performance, and DX.

For large projects, scoped (CSS Modules, CSS-in-JS) prevents name conflicts. Utility-first (Tailwind) reduces custom CSS but increases HTML class counts. Choose based on team preference and project size. Consistency matters more than the choice.

### 187. Styled components?

Styled Components is a CSS-in-JS library using template literals: `const Button = styled.button\`color: blue;\`;`. Benefits: scoped styles, dynamic styling via props, no class name conflicts.

Drawbacks: runtime overhead, bundle size (can be mitigated via Babel plugin), potential performance if overused. SSR requires careful setup. Good for component libraries and dynamic themes. For simpler apps, CSS Modules or Tailwind may suffice.

### 188. Tailwind?

Tailwind is a utility-first CSS framework: apply utility classes (flex, text-lg, bg-blue-500) instead of writing CSS. Large class names on elements but reduced custom CSS.

Benefits: consistency via design tokens, rapid prototyping, no unused CSS (purging). Drawbacks: verbose HTML, learning curve, slower than hand-written CSS. Popular for rapid development. Prefer for new projects; retrofitting to existing CSS is tedious.

### 189. Microfrontend?

Microfrontends decompose UI into independently deployable mini-applications sharing a shell/container. Module Federation (webpack 5) enables this. Benefits: independent releases, team/tech autonomy. Drawbacks: complexity, shared state/styling challenges, duplicated deps.

Use for large orgs with multiple teams. Smaller projects should start monolithic, refactor to microfrontends if scaling demands warrant. Coordinate carefully: shared APIs, styling, routing, and state management.

### 190. Module federation?

Module Federation (webpack 5+) enables dynamic loading of remote modules at runtime. One app exposes modules; others consume them. Enables true microfrontends.

Setup: webpack config with federationPlugin, shared dependencies. Runtime dynamic loading. Complex but powerful for scaling large multi-team projects. Requires discipline in versioning, testing, and API stability.

### 191. Testing React?

Test frameworks: Jest (unit), React Testing Library (component semantics), Cypress/Playwright (e2e). Focus on user interactions, not implementation. Test-first development (TDD) or test alongside development.

Key: test behaviors, not internals. Query by role/label (user-facing), not by test IDs (fragile). Mock APIs, not components. Achieve good coverage (critical paths, edge cases) without chasing 100%.

### 192. Jest?

Jest is a unit testing framework with snapshot testing, mocking, and built-in assertions. Run with `npm test`. Mock modules, timers, and APIs. Snapshots capture output for regression detection (use carefully, review diffs).

Jest pairs with React Testing Library for component testing. Strong matchers, fast, good DX. Standard for React projects.

### 193. React Testing Library?

React Testing Library focuses on testing components as users interact, not internals. Queries: getBy (throws), queryBy (null), findBy (async). Never test implementation details (state, refs).

Encourage good practices (accessible queries, user-perspective testing). Pairs perfectly with Jest. Learn to avoid testing Library shortcuts and anti-patterns (waitFor, within overuse).

### 194. Snapshot testing?

Snapshots capture rendered output and flag diffs in future runs. Useful for catching regressions in large component outputs. Warning: snapshots rot if not maintained. Review snapshot diffs carefully; don't blindly accept changes.

Use snapshots sparingly (large outputs, stable UIs). Prefer specific assertions (text content, attributes) for clarity. Snapshot tests catch changes, not correctness.

### 195. Mocking APIs?

Mock APIs in tests using libraries: MSW (Mock Service Worker, intercepting fetch/XHR), jest.mock, or API client mocking. MSW is powerful (network-level mocking) and decouples test setup from implementation.

Mock at the right level: API mocking (MSW) tests real API integration; jest.mock tests component logic in isolation. Combined approach balances coverage and test speed.

### 196. Performance profiling?

React DevTools Profiler measures render times, re-render causes, and component interactions. Chrome DevTools tracks Network, Performance (main thread), and Memory. Tools: Lighthouse (audit), WebPageTest (detailed).

Profile real user loads, not dev server. Identify bottlenecks: slow renders, large bundles, network waterfalls. Prioritize high-impact fixes. Continuous monitoring catches regressions.

### 197. React DevTools?

React DevTools browser extension enables component tree inspection, props/state viewing, and Profiler. Essential for debugging. View which hooks are in a component, inspect context values, track re-renders.

Master React DevTools for efficient debugging. Pair with browser DevTools for network, performance, and memory insights.

### 198. State normalization?

State normalization flattens nested structures, storing data by ID to avoid duplication and simplify updates. `{ users: { 1: {name: "John"}, 2: {...} } }` vs nested `{ users: [{id: 1, name: "John"}] }`.

Benefits: avoid updating deep nests, prevent stale duplicates. Drawbacks: denormalization required for display, boilerplate. Use for large, complex state. Redux (reselect library) and Entity adapters help. ORM-like libraries (Reselect, Immer) ease normalized updates.

### 199. Virtualization lists?

Virtualization renders only visible list items (+ buffer), drastically reducing DOM nodes for huge lists. Libraries: react-window, react-virtualized. Enables smooth scrolling through millions of items.

Essential for performance with large lists. Fixed item height simplifies virtualization; variable heights require measuring. Test scrolling smoothness and edge cases (rapid scrolling, item addition/removal).

### 200. Large data rendering?

Strategies: virtualization (visible items), pagination (page-by-page), lazy loading (as you scroll), or aggregation (roll up in backend). Combine with filtering/search for manageability.

Choose based on data characteristics and UX requirements. Most users prefer pagination or infinite scroll over full-page loads. Virtualization suits static lists; pagination suits navigable datasets. Backend aggregation is preferred when feasible.

## Section 5 — Real-Time Systems / WebSockets (Q201–Q250)

### 201. How WebSockets work?

WebSocket is a full-duplex communication protocol over TCP enabling persistent bidirectional connections. Client initiates HTTP upgrade, server accepts, and both can send messages anytime (no request/response cycle like HTTP). Browsers expose via WebSocket API: `new WebSocket('ws://host')`. Messages are frames with type (text, binary) controlling encoding.

Use WebSockets for low-latency, server-initiated updates (chat, live feeds, collaborative editing, multiplayer games). HTTP polling is inefficient (frequent requests); Server-Sent Events work for one-way server-to-client streams. WebSockets handle bidirectional, real-time scenarios. Plan for connection state, reconnection, and message ordering at scale.

### 202. HTTP vs WebSocket?

HTTP is request-response: client initiates, server responds, connection closes. Stateless, cacheable, scalable via stateless servers. WebSocket is persistent connection: either side sends data, low-latency, stateful (server tracks connections).

Use HTTP for simple req/resp (APIs, static content). Use WebSocket for low-latency bidirectional (chat, gaming, live updates). Hybrid: REST for state mutation, WebSocket for notifications/live data.

### 203. Handshake process?

WebSocket handshake: client sends HTTP Upgrade request with Sec-WebSocket-Key header; server responds 101 Switching Protocols with Sec-WebSocket-Accept (derived from key). Protocol switches to WebSocket. Both parties can now send frames.

Handshake is HTTP-compatible (proxies, firewalls allow), then binary framing takes over. Understanding the handshake helps troubleshoot connection issues (CORS, header mismatches).

### 204. Scaling WebSockets?

Single server handles thousands of connections (event-loop runtime: Node, Netty). Beyond single server, challenges: distributing connections, delivering messages across servers, and maintaining state.

Strategies: load balance connections (sticky sessions via IP hash or session affinity), use message broker (Redis Pub/Sub, Kafka) for cross-server messaging, and store session data in distributed store (Redis). Horizontal scaling requires careful routing and messaging patterns.

### 205. Sticky sessions?

Sticky sessions route all requests from a client to the same server (enabled by IP hash or session cookie). Necessary for stateful connections (WebSockets) without distributed state.

Downside: server failure loses client session; rebalancing during scaling is complex. For true horizontal scaling, decouple state into a distributed store and use load balancers without stickiness.

### 206. Message ordering?

WebSocket message order is guaranteed within a single connection (TCP guarantees). For multiple producers/servers sending to a single client, messages may interleave or arrive out of order.

Implement message sequencing: client tracks received sequence numbers, reorders if needed. Server publishes to a message queue ensuring ordered delivery. Design carefully for ordering requirements (critical for state consistency).

### 207. Reconnection strategies?

Clients should handle disconnections (network loss, server restart) and reconnect automatically. Strategies: exponential backoff (1s, 2s, 4s, ..., max 30s) to avoid overwhelming servers, jitter (randomize backoff) to prevent thundering herd, and connection timeouts to detect dead connections.

Implement with client libraries (Socket.io, SockJS) that handle reconnection logic. Server should persist undelivered messages (queues) or resync state on reconnect. Design for resilience and eventual consistency during brief disconnections.

### 208. Heartbeats?

Heartbeats (keep-alives) are periodic messages (ping/pong or app-level) sent from server to client (or both) to detect stale connections. WebSocket protocol has built-in ping/pong frames; apps can implement custom heartbeats.

Set interval appropriately (30-60s) to balance overhead and detection speed. Detects broken connections (network disconnect, crashed peer). Many proxies close idle connections; heartbeats prevent this. Pair with timeouts: if pong not received, connection is dead.

### 209. Pub/Sub systems?

Pub/Sub (publish-subscribe) decouples message senders (publishers) from receivers (subscribers). Publishers emit events to topics; subscribers registered to topics receive them. Enables N-to-M communication patterns.

Redis Pub/Sub, Kafka, RabbitMQ, and cloud services (AWS SNS/SQS, GCP Pub/Sub) implement Pub/Sub. Benefits: decoupling, scalability. Drawbacks: eventual delivery (Kafka/durable), no persistence (Redis), added complexity. Critical for event-driven architecture.

### 210. Redis pub/sub?

Redis Pub/Sub sends messages to subscribers in real-time but doesn't persist. Publishers publish to channels; subscribers receive immediately. Simple, low-latency, high throughput.

Limitation: no message history (subscribers miss messages published before subscription). Use for real-time notifications (live feeds). For durability and replay, use Kafka instead.

### 211. Kafka vs WebSocket?

Kafka is a distributed event log (persistent messages, partitions, consumer groups). WebSocket is a bidirectional network connection (for real-time messages, low-latency). Kafka survives consumer downtime, supports replay, scales to massive throughput. WebSocket is immediate, point-to-point, suitable for live interaction.

Combine: WebSocket for live client interaction, Kafka for robust server-side event processing and durability.

### 212. Load balancing sockets?

Load balance WebSocket connections via Layer 4 (TCP/IP) hash (client IP, port -> server) or Layer 7 (HTTP, custom logic). Sticky routing ensures reconnects go to the same server (without distributed state).

For true scaling, add a message broker (Redis, Kafka) and decouple socket handling from app logic. Clients connect to any server; servers route messages via broker. Eliminates sticky requirement and enables zero-downtime deployments.

### 213. Message queues? (Webocket context)

Client-side message queues buffer outgoing messages during connectivity loss, sending on reconnect. Server-side queues store messages for offline clients, delivery on next connect.

Implement for reliability: clients queue messages, retry failures, acknowledge delivery. Servers queue undelivered messages, limited by TTL/size. Pair with unique client IDs and idempotent consumption.

### 214. Latency optimization?

Minimize latency in real-time systems: close geographic proximity (CDN, regional servers), efficient serialization (binary, protobuf, not JSON), batching (collect messages, send together), and avoid blocking operations.

Monitor end-to-end latency (client timestamp, server echo, client measure). Profile bottlenecks: network, serialization, server processing. For gaming/trading, sub-100ms is critical; for chat, sub-second is acceptable. Design for use case requirements.

### 215. Real-time architecture?

Real-time systems combine WebSockets (low-latency) with message queues (durability), caches (speed), and event streams (replay/analytics). Typical flow: client connects via WebSocket, sends/receives messages, broker persists for reliability, other services consume events.

Design for resilience: degrade gracefully on connection loss, handle order-of-arrival, implement deduplication. Monitor latency, message volume, and connection health. Use load balancers and distributed state to scale horizontally.

### 216. Chat system design?

Components: WebSocket server (connection management), message store (durability), user service (auth, profiles), read receipts (who's online), presence (typing indicators). Users connect, send messages (broadcast to recipients), store in DB. Online users receive immediately; offline users retrieve on next login.

Scale: partition messages by room/channel, use Redis for online presence/typing indicators, Kafka for durability, multiple WebSocket servers behind load balancer. Test rapid message rates, large rooms, and reconnection storms.

### 217. Presence tracking?

Track which users are online, in which rooms, their status (active, idle, away). Implement via Redis (in-memory, fast), update on connect/disconnect and heartbeat. Broadcast presence changes to interested users.

Challenges: eventual consistency (presence changes propagate), stale status on crashes. Use heartbeats and timeouts for detection. Balance accuracy with overhead.

### 218. Message delivery guarantees?

At-most-once (fire-and-forget, some loss), at-least-once (retry, possible duplicates), exactly-once (no loss, no duplication, hardest). Message ID + idempotent processing prevents duplicate effects even with at-least-once delivery.

Most real-time systems use at-least-once with deduplication (cheaper than exactly-once consensus). Kafka supports all modes; choose based on tolerance for loss vs latency impact.

### 219. Offline handling?

Handle dropped clients: store undelivered messages (bounded queue), resync state (send full state or delta) on reconnect, and timeout stale messages. For critical data, implement client-side persistence (localStorage) and sync with server.

Strategies: message queues (server buffers), event sourcing (replay from log), or snapshots (send last N messages). Complexity increases with offline time; balance coverage and resource constraints.

### 220. Backpressure?

Backpressure is a mechanism slowing producers when consumers can't keep up. Without it, queues overflow and memory surges. Implement via: producer waiting (blocked until consumer processes), dropping old messages, or rate limiting.

TCP has built-in flow control. For application-level Pub/Sub, implement explicit backpressure: if queue depth exceeds threshold, slow producers (return error, drop, or pause). Critical for high-throughput systems to prevent cascading failures.

### 221. Debouncing?

Debouncing delays action until after a timeout from last event (prevents rapid re-firing). Example: user types, debounce 300ms, then send search query. Reduces server load.

Implement client-side with setTimeout. Pair with server-side rate limiting for defense.

### 222. Throttling?

Throttling limits action frequency to at most once per interval (e.g., scroll event fires at max 60/sec). Reduces CPU/network load from high-frequency events.

Implement via scheduled callbacks or request debouncing. Pair rate limiting server-side.

### 223. Event delegation?

Event delegation uses a single listener on a parent for many child events (bubbling). Reduces listeners, improves memory. Useful for dynamic content (e.g., click handler on table delegating to rows).

Understand event bubbling phases (capture, target, bubble) to delegate correctly. Avoid over-delegation (performance trade-offs with filtering logic).

### 224. Browser rendering pipeline?

Steps: parse HTML/CSS → DOM/CSSOM trees → render tree (layout) → paint (draw pixels) → composite (layers). JavaScript blocks parsing. CSS/images block rendering. Optimization: critical path (minimize blocking resources, inline critical CSS), defer non-critical JS.

Use DevTools timeline to identify bottlenecks. Techniques: async/defer scripts, CSS media queries, lazy load images/fonts.

### 225. Layout thrashing?

Layout thrashing is repeated forced layouts (layout, read properties, modify, layout again). Causes jank and poor performance. Example: loop modifying DOM and reading offsetWidth.

Avoid by batching reads/writes: read all properties first, batch DOM changes, then layout recomputes once. Use requestAnimationFrame to group visual updates.

### 226. SEO in React?

React SPAs lack SEO by default (robots see empty HTML). Strategies: server-side rendering (SSR, send rendered HTML), prerendering (build time), or dynamic rendering (detect bots, serve pre-rendered). Use react-helmet or next.js for meta tags, structured data.

For modern bots (Google), CSR with good content works. For older bots or social sharing, implement SSR or prerender. Verify with Search Console.

### 227. SSR vs CSR?

CSR (Client-Side Rendering): browser downloads JS, renders. Fast interaction after load, but slow initial load, poor SEO. SSR (Server-Side Rendering): server renders HTML, sends to client, hydrates. Fast FCP, better SEO, but server load, complex setup.

Use CSR for internal tools, SSR for public content. Next.js enables hybrid: SSR for critical pages, CSR for others. Choose based on performance and SEO requirements.

### 228. Next.js basics?

Next.js is a React framework for SSR, SSG, ISR, and API routes. Pages directory maps to routes, getServerSideProps/getStaticProps for data. Built-in optimizations: code splitting, image lazy load, font optimization.

Simplifies SSR setup, provides structure, and enables hybrid rendering strategies. Standard for production React apps needing SEO or performance.

### 229. Frontend security?

Prevent XSS: escape user input, use DOMContentLoaded (not innerHTML), React auto-escapes. Prevent CSRF: validate origins, use CSRF tokens for forms. Secure storage: HTTPS for transport, localStorage (not cookies) for non-sensitive data. Never store secrets client-side.

Use security headers (CSP, X-Frame-Options), keep dependencies updated, use subresource integrity. Audit regularly with tools (OWASP ZAP, Burp Suite). Security is everyone's responsibility.

### 230. Infinite scroll?

Infinite scroll loads more items as user scrolls near bottom (better UX than pagination for discovery). Implement with IntersectionObserver (trigger load when sentinel element visible), combine with virtualization for large datasets.

Challenges: scroll position loss (on back), SEO (content below fold), state management. Test edge cases: rapid scrolling, network latency, empty states. For products, A/B test against pagination.

## Section 6 — System Design (Q231–Q270)

### 231. Design a chat system?

Core: users connect (WebSocket), send messages, others receive in real-time. Store messages in DB for history. Components: chat server (connection handling, routing), message store (DB/Kafka), user service, file storage (media), notifications.

Scale: shard by room/user, use Redis for online presence, Kafka for durability, multiple servers behind LB. Handle offline users (queue messages), delivery receipts, typing indicators. A/B test UI (real-time vs polling). Expect high concurrency and message volume.

### 232. Design URL shortener?

Core: long URL → short URL (encode hash), lookup short → redirect to long. Database: short URL (key), long URL (value), creation timestamp. Use hash function (MD5/SHA1 first 6-7 chars) to generate shorts, handle collisions (retry with different hash).

Scale: shard by short URL hash, cache hot URLs (Redis), async analytics in parallel. Serve redirects via CDN (low-latency). Handle abuse (rate limit, spam detection). Monitor 404s (broken shorts).

### 233. Design notification system?

Users subscribe to events; system sends notifications (email, SMS, push). Components: event producer (app), queue (Kafka), worker (process notifications), delivery service (email/SMS provider), storage (notification history).

Scale: decouple via queue, parallelize workers, retry failed deliveries, implement backoff. Handle rate limiting (user preferences), batching (cost optimization). Provide templates, scheduling (send later), and unsubscribe.

### 234. Design file storage?

Core: upload file, get metadata, download. Store files on object storage (S3, GCS), metadata in DB. Components: API gateway (auth, rate limit), upload handler, storage backend, cache (CDN).

Scale: multipart uploads (parallel), deduplication (content hash), replication (availability), versioning. Handle large files (torrent download), encryption, and quarantine malicious files. Consider cost (storage, egress bandwidth).

### 235. Design rate limiter?

Limit requests per user/IP to prevent abuse. Algorithms: token bucket (fixed rate, burst), leaky bucket (smooth rate), sliding window (precise, stateful). Store limits in Redis, return 429 with Retry-After.

Design for distributed systems (Redis cluster), variable limits (free/premium), and graceful degradation (allow burst on limit hit). Monitor and alert on unusual patterns.

### 236. Design payment system?

Core: user initiates payment, process via payment gateway (Stripe, PayPal), store transaction, fulfill order. Handle: concurrency (idempotent operations), failures (retries, rollbacks), fraud detection, compliance (PCI, SOX).

Use message queues for async processing, store pending transactions, implement reconciliation with payment gateway. Webhook handling for async confirmations. Zero-downtime upgrades with feature flags. Test thoroughly with test payment methods.

### 237. Design microservices architecture?

Decompose monolith into services (users, orders, payments, inventory, shipping). Each service owns its data, minimal shared state. Communicate via REST/gRPC or events. Use API gateway for unified entry, service discovery (Kubernetes, Consul).

Design for: independent scaling, deployment, tech choices. Document contracts, implement versioning, provide SDKs. Plan for failures (cascades, timeouts, circuit breakers). Operational complexity higher; suitable for large orgs/products.

### 238. Horizontal scaling?

Add more servers (instances) in parallel instead of upgrading single server (vertical). Benefits: handle more load, fault tolerance. Challenges: state sharing (sessions, caches), consistency (eventual), coordination.

Design stateless services, use external state stores (Redis, DB), load balance, and implement health checks. Cost-effective and cloud-friendly (add/remove on demand).

### 239. Vertical scaling?

Upgrade existing server (CPU, RAM). Simple but has limits (hardware ceiling), single point of failure. Sufficient for small services with moderate load.

Combine with horizontal: start vertical (simpler), then horizontal when needed.

### 240. Load balancing?

Distribute traffic across servers. Algorithms: round-robin (even distribution), least connections (lowest active), IP hash (sticky sessions). Layer 4 (TCP) for raw traffic; Layer 7 (HTTP) for smart routing (URL, hostname).

Use health checks, graceful drains, and monitor backend availability. CDN for geographic distribution, API gateway for cross-cutting concerns.

### 241. CDN?

CDN (Content Delivery Network) caches content on edge servers near users, reducing latency and origin load. Perfect for static assets (JS, CSS, images), APIs (regional endpoints).

Configure cache headers, invalidation strategies, and failover to origin. Reduces infrastructure cost and improves user experience significantly.

### 242. Caching layers?

Multi-level caching: CPU cache, application cache (in-memory), distributed cache (Redis), CDN cache, HTTP cache (browser). Each layer reduces load on deeper layers.

Design: identify hot data, TTL, invalidation strategy (event-driven, time-based), and freshness tolerance. Cache stampedes: use collapses queries, probabilistic early expiry. Monitor hit rates.

### 243. Cache invalidation?

Invalidate cache to ensure freshness. Strategies: TTL (time-based), event-based (update event triggers invalidation), LRU (evict old entries), versioning (change key on update).

Classic hard problem: design explicit invalidation. Pair with monitoring for cache misses/staleness anomalies.

### 244. Database scaling?

Optimize within single DB: indices, query tuning, connection pooling. Beyond: read replicas (horizontal read), sharding (horizontal write), caching layer. Replication lag acceptable for reads; sharding adds complexity (transaction, joins across shards).

Choose based on workload: mostly reads → replicas, high-write → sharding. Consider operational overhead.

### 245. Sharding?

Partition data by shard key across multiple DB instances. Enables write scaling. Challenges: even distribution (avoid hotspots), shard rebalancing (expensive), and cross-shard operations (expensive/not transactional).

Plan shard key and rebalancing. Consistent hashing or fixed partition schemes. Use coordination service (ZooKeeper, etcd) for shard topology. Handle shard splits/merges without downtime.

### 246. Replication?

Copy data across instances: primary (writes), replicas (reads). Improves availability and read throughput. Consistency models: strong (sync, slow), weak (async, fast).

Monitor replication lag, handle failover (elect new primary). For critical data, synchronous replication; for analytics, asynchronous. Combine with backups for DR.

### 247. Event-driven systems?

Services publish events (domain events), others subscribe and react. Decouples services, improves scalability. Store events (event store), replay for state reconstruction (event sourcing).

Complexity: eventual consistency, ordering, idempotency. Use Kafka for durability and ordering. Design for distributed tracing, versioning, and backward compatibility.

### 248. Queue-based systems?

Decouple producers/consumers via message queues (Kafka, RabbitMQ, SQS). Producers send messages (async), workers consume. Scales independently.

Benefits: decoupling, resilience (survives consumer downtime), load leveling. Complexity: eventual consistency, debugging. Monitor queue depth, consumer lag.

### 249. Fault tolerance?

Systems fail; design for resilience. Strategies: redundancy (N+1), health checking (detect failures), auto-failover (elect new leader), graceful degradation (shedding non-critical features).

Design for partial failures (some servers down, services slow, network partitions). Use circuit breakers, timeouts, retries. Test failure scenarios (chaos engineering). Document runbooks.

### 250. Circuit breakers?

Stop requests to failing services, return cached/default responses. States: closed (normal), open (failing, short-circuit), half-open (test recovery). Configurable thresholds (consecutive failures, error rate).

Prevent cascading failures. Pair with exponential backoff for retries. Monitor state changes and alert. Libraries: Resilience4j, Hystrix.

### 251. Monitoring?

Observe system health: uptime, error rates, latency, throughput, cost. Collect metrics (Prometheus, Datadog), logs (ELK, Loki), traces (Jaeger). Alert on anomalies.

Custom metrics for domain logic. Distinguish symptoms (high latency) from causes (slow DB). Dashboard for visibility, runbooks for response. Continuous improvement from monitoring insights.

### 252. Observability?

Observability answers "what happened" from system outputs (logs, metrics, traces). Monitor multiple systems (infrastructure, app, DB) together. Structured logging (JSON), correlation IDs across requests, distributed tracing.

Better than alerting: proactive diagnosis, anomaly detection, capacity planning. Tools: Honeycomb, DataDog, New Relic. Invest in observability; it pays off in incident response.

### 253. Logging architecture?

Centralized logging: applications log to aggregator (Fluentd, Logstash), stored (Elasticsearch), indexed (Kibana). Enables search/alerting across all services.

Design: structured logs (JSON), contextual data (user ID, trace ID), severity levels. Filter high-volume logs (sample). Cost: storage and compute for indexing. Balance visibility and cost.

### 254. Metrics?

Metrics capture numeric data (latency, requests, errors, memory). Time-series DBs store efficiently (Prometheus, InfluxDB). Alert on thresholds, track trends.

Types: counters (monotonic, request count), gauges (current value, memory), histograms (distributions). Cardinality explosion (too many label combinations) kills systems; design carefully.

### 255. Distributed tracing?

Trace a request end-to-end across services, showing spans (service calls) and latency. Tools: Jaeger, Zipkin. Enables fault diagnosis ("where did it slow?"). Pair with logs and metrics.

Sampling (not all traces, cost) vs. full tracing (visibility). Correlation IDs propagate trace context. Critical for microservices debugging.

### 256. Consistency models?

Strong consistency (all replicas always agree, slower), weak consistency (replicas may diverge, eventual consistency — all converge given time, faster). CAP theorem: choose consistency or availability under partition.

Most systems choose eventual consistency for availability/speed. Design apps to tolerate stale data, use versioning, implement compensating transactions if needed.

### 257. CAP theorem?

Consistency (all replicas same), Availability (system always responds), Partition tolerance (survives network splits). Can't have all three; partition tolerance is non-negotiable in distributed systems.

Choose: CP (prioritize data integrity), AP (prioritize availability/resilience). Systems often tune one dimension (consistency strength, replication latency).

### 258. Data partitioning?

Partition data by range (date, ID) or hash (ID mod N) for scalability. Range allows efficient range queries but can create hotspots (popular date range). Hash distributes evenly but loses range query benefit.

Design partition key carefully (stable, uniform distribution). Monitor hotspots and rebalance if needed. Larger partitions; fewer partitions.

### 259. High availability?

Systems tolerate failures and maintain service. Patterns: redundancy, health monitoring, automated failover, graceful degradation. RTO (recovery time), RPO (data loss tolerance) guide design.

Multi-region for geo-resilience. Data replication, leader election, and coordination services essential. Test failovers regularly, document runbooks, maintain on-call rotations.

### 260. Disaster recovery?

Plan for catastrophic failure (datacenter down, data corruption). Backup to geographically distant region, test recovery regularly. RTO (how fast to recover), RPO (how much data loss acceptable).

Automated backups, versioning, and point-in-time recovery. For critical data, near-sync replication (acceptable RPO). Document recovery procedures and test them.

### 261. Multi-region deployment?

Deploy services across regions (continents) for latency (serve users locally), availability (survive region failure), and compliance (data residency). Challenges: data consistency (eventual), operational complexity, cost.

Primary-replica or multi-master replication. Route users to nearest region. Test failover between regions. Coordinate deployments. Monitor latency and replication lag.

### 262. Stateless vs stateful?

Stateless services don't hold client data (easily replicated, scalable). Stateful services store client state (persistent, harder to scale). Prefer stateless; store state in DB/cache. Stateful is acceptable for session-specific data (cache connections temporarily).

Design: decouple state from compute. Enables horizontal scaling, zero-downtime deployments.

### 263. Idempotency?

Idempotent operations return the same result if executed multiple times. Critical for retries: if request fails, retry safely without duplicating effect. Implement via idempotency keys (client ID + request ID) mapped to responses.

Design APIs to be idempotent (PUT, DELETE naturally are). Store recent responses (Redis) for deduplication. Essential for distributed, fault-prone systems.

### 264. Retry strategies?

Retry failed requests with exponential backoff (1s, 2s, 4s, ..., max) and jitter (randomize to avoid thundering herd). Circuit breakers prevent retrying failing services. Idempotency enables safe retries.

Not all errors are retryable (4xx errors, usually not; 5xx, often retryable). Document retry policies. Avoid retry storms (rate limit, max retries).

### 265. Backoff algorithms?

Exponential backoff: wait increases exponentially per retry (2^attempt * base). Linear backoff: increases linearly. Jitter: add randomness to prevent synchronized retries.

Exponential favored for cascading failures (load decreases faster). Configure max wait (prevent forever waits). Test under real failure scenarios.

### 266. API design at scale?

Version APIs (URL path, header), maintain backward compatibility, use hypermedia (HATEOAS, links) for discoverability. Paginate results, sort stably, filter server-side. Rate limit, authenticate, authorize. Document with OpenAPI.

Status codes: 200 (OK), 201 (Created), 204 (No Content), 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found), 409 (Conflict), 429 (Rate Limited), 500 (Server Error). Be consistent.

### 267. Security at scale?

Defense-in-depth: secure transport (TLS), authentication (OAuth2, SAML), authorization (RBAC, ABAC), input validation (SQL injection, XSS), secrets management (Vault), audit logging. Encrypt at rest and in transit.

Regular security audits, dependency updates, penetration testing. Breach response procedures. Compliance (GDPR, HIPAA, PCI). Security is not an afterthought.

### 268. Cost optimization?

Measure cloud costs (compute, storage, egress bandwidth). Optimize: right-size instances, reserved capacity, auto-scaling, caching, compression, CDN. Monitor and alert on anomalies.

Balance cost and performance. Prefer managed services when operational overhead isn't justified. Negotiate volume discounts with cloud providers. FinOps practices help.

### 269. Performance optimization?

Profile identify bottlenecks (CPU, memory, I/O, network). Optimize incrementally: algorithms, caching, batching, async, parallel processing. Measure before/after. Keep performance regressions from accumulating.

Use APMs (Datadog, New Relic) for continuous monitoring. Load test and capacity plan. Optimize expensive code paths. Test at scale.

### 270. Trade-off decisions?

Architecture involves constant tradeoffs: consistency vs availability, latency vs throughput, simplicity vs performance, cost vs capability. Document reasoning: why this choice, not alternatives, tradeoffs accepted.

Revisit as requirements change. Be pragmatic: early premature optimization risks; late optimization is expensive. Measure, decide, validate.

## Section 7 — AWS / DevOps (Q271–Q290)

### 271. AWS architecture basics?

AWS provides cloud services: compute (EC2, Lambda), storage (S3, EBS), database (RDS, DynamoDB), networking (VPC, ALB), messaging (SQS, SNS), and more. Design for high availability (multi-AZ), scalability (auto-scaling), and cost-efficiency.

Use managed services to reduce operational burden. Design for failure (redundancy, backups, DR). Security groups control inbound/outbound, IAM grants permissions. Cost: pay-as-you-use; monitor and optimize.

### 272. EC2?

EC2 (Elastic Compute Cloud) provides virtual machines (instances) on-demand. Choose instance type (CPU, RAM, storage, network), OS, security group. Scale via auto-scaling groups (add/remove instances based on load). Cost: on-demand, reserved (cheaper), spot (cheapest, interruptible).

Design: stateless, idempotent instances replaced easily. Pair with load balancers and health checks. Use Terraform/CloudFormation for infrastructure-as-code.

### 273. S3?

S3 (Simple Storage Service) is object storage: store/retrieve files (buckets, keys). Scalable, durable (11 9's), available globally. Pricing: storage, requests, transfer. Integrates with CloudFront (CDN), S3 Select (query in-place), Glacier (archival).

Design: use versioning, enable logging, secure with bucket policies/ACLs, use SSE (encryption). Lifecycle policies transition old objects to cheaper tiers. Multipart uploads for large objects.

### 274. RDS?

RDS (Relational Database Service) is managed SQL database (PostgreSQL, MySQL, Oracle, SQL Server). Handles backups, patches, replication (multi-AZ for HA). Scaling: upgrade instance size (vertical) or read replicas (read-only, horizontal).

Cheaper than self-managed, but less control. Monitor performance (metrics), use parameter groups for tuning. Plan capacity, monitor costs (storage, IOPS).

### 275. DynamoDB?

DynamoDB is NoSQL, fully managed, serverless (no capacity planning). On-demand or provisioned throughput. Supports single-digit latency at scale, global tables (multi-region).

Limitations: no joins, eventual consistency by default, limited query patterns (design around partition key). Strong eventually consistent reads cost more. Good for real-time, high-throughput applications.

### 276. Lambda?

Lambda is serverless compute: upload code, AWS manages infrastructure. Pay for execution time (milliseconds), not idle. Auto-scales, event-driven (S3 upload, API Gateway, SQS, etc.).

Limitations: timeout (15 min), cold start latency, environment constraints (languages, libraries). Good for event-driven, occasional workloads. Not for long-running tasks or those needing persistent state.

### 277. API Gateway?

API Gateway provides REST/HTTP API frontend, routes to Lambda, EC2, or other backends. Handles: request validation, transformation, authentication, rate limiting, logging.

Enable CORS, request/response mapping, request caching. Use stages (dev, prod). Pair with Lambda for serverless APIs. Simpler ALB for complex routing (multiple backends, protocols).

### 278. CloudFront?

CloudFront is AWS's CDN: cache content on edge locations globally. Reduce latency for users, offload origin. Supports HTTP/2, HTTP/3, DDoS protection (Shield).

Configure origins (S3, ALB, custom), cache behaviors (by path, header), invalidation (after deployments). Cost: data transfer (cheaper than origin), requests.

### 279. IAM?

IAM (Identity and Access Management) grants AWS resource permissions. Principle of least privilege: grant only needed permissions. Resources (S3 bucket, EC2 instance), actions (s3:GetObject), principals (users, services).

Policies are JSON. Use roles for services (Lambda, EC2 accessing other services). Enable MFA for human users, rotate keys. Audit with CloudTrail. Complex but critical for security.

### 280. VPC?

VPC (Virtual Private Cloud) isolates network: subnets (AZs), route tables (routing), security groups (stateful firewall), NACLs (network access control, stateless). Design: public subnets (ALB, NAT), private subnets (apps, DB).

Use VPC peering or Transit Gateway to connect VPCs. Enable VPC Flow Logs for debugging. Cost: minimal, but data transfer across regions expensive.

### 281. Load balancer types?

ALB (Application Load Balancer): Layer 7 (HTTP), route by hostname/path, target groups. NLB (Network Load Balancer): Layer 4 (TCP/UDP), ultra-high throughput, low latency. CLB (Classic): older, simpler.

Use ALB for most web apps, NLB for extreme performance or non-HTTP protocols. Health checks ensure traffic only to healthy targets. Pricing per LB and processed bytes.

### 282. Auto scaling?

Auto Scaling Groups (ASG) add/remove EC2 instances based on metrics (CPU, custom). Define min, max, desired capacity. Policies: target tracking (maintain target metric), step scaling (based on alarm thresholds).

Pair with health checks and instance refresh for zero-downtime deployments. Cost: save money by scaling down during off-hours. Test scaling behavior under load.

### 283. Docker?

Docker containerizes applications: package code, dependencies, config as images. Containers are lightweight, portable, reproducible. Docker Compose orchest rates local containers; Docker Swarm or Kubernetes orchestrate at scale.

Build: Dockerfile defines layers (FROM, RUN, COPY, CMD). Push to registry (AWS ECR, Docker Hub). Run with resource limits. Security: scan images (Trivy, ECR scanning), use minimal base images.

### 284. Containerization?

Containers enable consistent deployment (works on dev, prod), rapid scaling, resource isolation. Orchestrators (Kubernetes, ECS) manage scheduling, networking, storage.

Mindset: loosely-coupled, stateless containers. Log to stdout (captured by orchestrator). Use health checks. Versioning: tag images semantically (v1.2.3).

### 285. Kubernetes basics?

Kubernetes orchestrates containers: nodes (machines), pods (containers), deployments (replicas), services (networking). YAML manifests define desired state; K8s reconciles to it.

Features: auto-scaling, self-healing, rolling updates, service discovery. Complexity: requires operational expertise. Managed K8s (EKS, GKE) reduce operational burden.

### 286. CI/CD pipelines?

CI (Continuous Integration): on every commit, build, test, push artifacts. CD (Continuous Deployment): automatically deploy to production. Tools: GitHub Actions, GitLab CI, Jenkins, CircleCI.

Design: fast feedback (10-15 min builds), parallel testing, automated deployments. Stages: lint, unit tests, integration tests, deploy to staging, deploy to prod (possibly manual approval). Rollback procedures.

### 287. Deployment strategies?

Blue-green: run two identical envs, switch traffic. Rolling: gradually replace old instances. Canary: route small traffic % to new version, monitor, expand. Feature flags: enable features per user without deployment.

Choose based on risk tolerance and rollback needs. Test deployments in staging. Automate rollback. Monitor for issues (error rates, latency).

### 288. Monitoring (CloudWatch)?

CloudWatch (AWS's monitoring service) collects metrics (EC2, RDS, Lambda), logs (applications, AWS services), and enables alarms. Custom metrics: publish application metrics.

Dashboard for visibility, alarms for notifications (SNS, PagerDuty). Logs Insights for querying (SQL-like). CloudTrail logs API calls for audit/compliance. Cost: storage and data scanned.

### 289. Infrastructure as Code?

IaC (Terraform, CloudFormation, CDK) defines infrastructure in code: versioned, reproducible, reviewable. Benefits: consistency, disaster recovery (redeploy), automation, documentation.

Terraform is provider-agnostic (AWS, GCP, Azure). CloudFormation is AWS-native, simpler for AWS-only. Modularize, test changes in staging, plan before applying. Secrets management (Vault, AWS Secrets Manager).

### 290. Security groups vs NACL?

Security groups (stateful): inbound/outbound rules per instance. NACLs (stateless): rules per subnet, require explicit return rules. Security groups are simpler, sufficient for most use cases.

NACLs provide defense-in-depth but are harder to reason about. Default deny, explicitly allow. Monitor and log (VPC Flow Logs).

## Section 8 — Security / Engineering Practices (Q291–Q300)

### 291. OWASP Top 10?

Top vulnerabilities: injection (SQL, command), broken auth, sensitive data exposure, XML external entities (XXE), broken access control, security misconfiguration, XSS, insecure deserialization, using components with known vulnerabilities, insufficient logging/monitoring.

Mitigate: input validation, parameterized queries, strong auth, encryption, regular updates, WAF, security headers. Annual updates reflect evolving threats.

### 292. SQL injection prevention?

Attacker inserts SQL via input (unsanitized). Prevent: parameterized queries/prepared statements (SQL template + data), input validation (whitelist), least privilege (DB user has minimal permissions).

Never concatenate SQL. Use ORM frameworks that use prepared statements by default (Hibernate, Entity Framework). Test with fuzzing.

### 293. XSS prevention?

Attacker injects scripts into pages. Prevent: escape output (context-aware: HTML, JS, URL, CSS escape), use frameworks auto-escaping (React auto-escapes), Content Security Policy (CSP, restrict script sources).

Use HTTPS, set secure/httponly flags on cookies. Sanitize user input for safe outputs (OWASP DOMPurify).

### 294. CSRF protection?

Attacker tricks user's browser to perform unwanted actions on authenticated site. Prevent: CSRF tokens (unique per request, validated server-side), SameSite cookies, origin checking, require POST for state-changing ops (not GET).

Tokens in forms; validate on server. SameSite (Strict/Lax) prevents cross-site cookie sending. For stateless APIs, CSRF is less relevant if not using cookies.

### 295. JWT security?

Don't store secrets in JWT (observable in token). Use short-lived tokens (15 min), refresh tokens (longer-lived) for renewal. Validate signature (verify against key), expiry, audience, issuer.

Use strong algorithms (RS256, not HS256 with weak secret). Ensure secure transport (HTTPS). Consider token rotation and revocation lists for sensitive operations.

### 296. HTTPS working?

HTTPS encrypts transport via TLS/SSL. Handshake: client and server exchange keys, encrypt subsequent data. Certificates bind identity (domain) to public key; trusted CAs issue certs.

Enable HSTS (enforce HTTPS), use strong ciphers (TLS 1.2+), rotate certificates before expiry. Cost: minimal (free via Let's Encrypt). Performance: negligible with modern hardware/protocols (HTTP/2, TLS 1.3).

### 297. Encryption basics?

Symmetric (same key to encrypt/decrypt, fast, key distribution hard): AES-256. Asymmetric (public key to encrypt, private key to decrypt, slow): RSA, ECDSA. Hash (one-way, collision-resistant): SHA-256.

Use symmetric for at-rest encryption (database, files); asymmetric for key exchange. Never invent crypto; use libraries. Secure key storage (Vault, HSM).

### 298. Secure coding practices?

Principle of least privilege: grant minimal permissions. Input validation: whitelist, sanitize. Output encoding: context-aware escaping. Dependency management: update regularly, audit for vulnerabilities (SAST, DAST).

Code review for security, static analysis (SonarQube, Semgrep), dynamic testing. Logging (without secrets), monitoring for anomalies. Security training for team.

### 299. Code review practices?

Code review catches issues early (bugs, security, quality). Process: author submits PR, reviewers suggest improvements, iterate, merge. Tools: GitHub, GitLab, Gerrit.

Review for: correctness, performance, security, style, tests. Avoid review fatigue (too many files). Automate trivial checks (linting, tests). Foster psychological safety; constructive feedback.

### 300. Handling production incidents?

Incident: service or system failure impacting users. Process: detect (alerting), triage (severity, impact), mitigate (restore functionality), investigate (root cause), remediate (fix), post-mortem (learnings).

On-call responsibilities: respond quickly, communicate with stakeholders, execute runbooks. Blameless culture: focus on systems, not individuals. Document post-mortems, implement action items. Regular incident simulations (games) improve preparedness.

