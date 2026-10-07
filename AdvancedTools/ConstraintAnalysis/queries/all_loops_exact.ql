/**
 * @name All Loops Exact
 * @description Exact loop detection - one result per source loop
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

// For each loop, find the canonical header, back edge, and exit
from Function f, Loop loop
where loop.getEnclosingFunction() = f
select 
  f.getQualifiedName(),
  getLoopId(loop),
  // Header: block containing condition (or first block for infinite loops)
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