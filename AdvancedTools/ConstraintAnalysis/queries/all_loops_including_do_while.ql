/**
 * @name All Loops Including Do-While
 * @description Detects all loops including do-while loops
 * @kind problem
 */
import cpp

string getBasicBlockId(BasicBlock bb) {
  exists(ControlFlowNode start, ControlFlowNode end |
    start = bb.getStart() and
    end = bb.getEnd() and
    result = start.getLocation().getStartLine() + "." + start.getLocation().getStartColumn() + 
             "_" + 
             end.getLocation().getEndLine() + "." + end.getLocation().getEndColumn()
  )
}

// Get unique identifier for a loop
string getLoopId(Loop loop) {
  result = loop.getLocation().getStartLine() + ":" + loop.toString()
}

// Predicate to check if a back edge belongs to a known Loop
predicate isKnownLoopBackEdge(BasicBlock source, BasicBlock target) {
  exists(Loop loop, BasicBlock header |
    (header.contains(loop.getCondition()) or
     (not exists(loop.getCondition()) and
      header.getEnclosingFunction() = loop.getEnclosingFunction() and
      header.getStart().getLocation().getStartLine() >= loop.getLocation().getStartLine() and
      header.getStart().getLocation().getStartLine() <= loop.getLocation().getStartLine() + 2)) and
    target = header and
    source.getASuccessor() = target and
    target.getASuccessor*() = source
  )
}

// Results from regular loops (while/for)
from Function f, Loop loop
where loop.getEnclosingFunction() = f
select 
  f.getQualifiedName(),
  getLoopId(loop),
  // Header: block containing condition
  min(BasicBlock header |
    (header.contains(loop.getCondition()) or
     (not exists(loop.getCondition()) and
      header.getEnclosingFunction() = f and
      header.getStart().getLocation().getStartLine() >= loop.getLocation().getStartLine() and
      header.getStart().getLocation().getStartLine() <= loop.getLocation().getStartLine() + 2)) and
    exists(BasicBlock back | back.getASuccessor() = header and header.getASuccessor*() = back) |
    getBasicBlockId(header)
  ),
  // Exit: first successor of header that's not a back edge
  min(BasicBlock exit, BasicBlock header |
    (header.contains(loop.getCondition()) or
     (not exists(loop.getCondition()) and
      header.getEnclosingFunction() = f and
      header.getStart().getLocation().getStartLine() >= loop.getLocation().getStartLine() and
      header.getStart().getLocation().getStartLine() <= loop.getLocation().getStartLine() + 2)) and
    exists(BasicBlock back | back.getASuccessor() = header and header.getASuccessor*() = back) and
    exit = header.getASuccessor() and
    not (exit.getASuccessor() = header and header.getASuccessor*() = exit) |
    getBasicBlockId(exit) + "@" + getBasicBlockId(header)
  ).regexpCapture("(.*)@.*", 1),
  // Back edge: deepest block that goes back to header
  max(BasicBlock back, BasicBlock header |
    (header.contains(loop.getCondition()) or
     (not exists(loop.getCondition()) and
      header.getEnclosingFunction() = f and
      header.getStart().getLocation().getStartLine() >= loop.getLocation().getStartLine() and
      header.getStart().getLocation().getStartLine() <= loop.getLocation().getStartLine() + 2)) and
    back.getASuccessor() = header and
    header.getASuccessor*() = back and
    back.getStart().getLocation().getStartLine() >= loop.getLocation().getStartLine() and
    back.getEnd().getLocation().getEndLine() <= loop.getLocation().getEndLine() |
    getBasicBlockId(back) order by back.getEnd().getLocation().getEndLine() desc
  )

or

// Results from do-while loops (not detected by Loop class)
from Function f, BasicBlock backEdgeSource, BasicBlock backEdgeTarget
where 
  f = backEdgeSource.getEnclosingFunction() and
  f = backEdgeTarget.getEnclosingFunction() and
  // It's a back edge
  backEdgeSource.getEnd().getLocation().getStartLine() > backEdgeTarget.getStart().getLocation().getStartLine() and
  backEdgeSource.getASuccessor() = backEdgeTarget and
  // It's not part of a known loop
  not isKnownLoopBackEdge(backEdgeSource, backEdgeTarget) and
  // There's a path from target back to source (it's actually a loop)
  backEdgeTarget.getASuccessor+() = backEdgeSource
select 
  f.getQualifiedName(),
  "DO_WHILE_" + backEdgeTarget.getStart().getLocation().getStartLine(),
  getBasicBlockId(backEdgeTarget),  // Loop header (where back edge points to)
  // Find exit block - the FALSE branch from the condition block
  min(BasicBlock exit |
    exit = backEdgeSource.getAFalseSuccessor() or
    (not exists(backEdgeSource.getAFalseSuccessor()) and 
     exit = backEdgeSource.getASuccessor() and
     exit != backEdgeTarget) |
    getBasicBlockId(exit)
  ),
  getBasicBlockId(backEdgeSource)   // Back edge source (condition block)