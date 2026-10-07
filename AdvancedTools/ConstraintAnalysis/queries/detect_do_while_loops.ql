/**
 * @name Detect Do-While Loops
 * @description Detects do-while loops by identifying back edges that don't correspond to CodeQL Loop objects
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

// Predicate to check if a back edge belongs to a known Loop
predicate isKnownLoopBackEdge(BasicBlock source, BasicBlock target) {
  exists(Loop loop |
    // The back edge is part of a recognized loop
    target.contains(loop.getCondition()) and
    source.getASuccessor() = target and
    target.getASuccessor*() = source
  )
}

// Find do-while patterns: back edges that aren't part of recognized loops
from Function f, BasicBlock backEdgeSource, BasicBlock backEdgeTarget
where 
  f = backEdgeSource.getEnclosingFunction() and
  f = backEdgeTarget.getEnclosingFunction() and
  // It's a back edge (source comes after target in the code)
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